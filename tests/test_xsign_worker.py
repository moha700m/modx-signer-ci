"""Unit tests for the XSign GitHub worker.

These tests stub the network layer (``requests.Session.request``) so they run
anywhere, including non-macOS CI, and never touch real signing material.
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import types
import unittest
from unittest import mock

import requests

import xsign_worker as xw


class _FakeResponse:
    def __init__(self, status_code: int, payload: dict | None = None, text: str = '') -> None:
        self.status_code = status_code
        self._payload = payload or {}
        self.text = text or json.dumps(self._payload)

    def json(self) -> dict:
        return self._payload


def _client(max_retry_seconds: float = 5.0) -> xw.XSignClient:
    with mock.patch.dict(os.environ, {'XSIGN_BASE_URL': 'https://xsign.test/app/demo'}, clear=False):
        client = xw.XSignClient(max_retry_seconds=max_retry_seconds)
    return client


class ConfigurationTests(unittest.TestCase):
    def test_legacy_appdeploy_worker_url_is_normalized(self) -> None:
        with mock.patch.dict(os.environ, {'XSIGN_BASE_URL': 'https://api-v2.appdeploy.ai/app/xsign-demo'}, clear=False):
            self.assertEqual(xw.configured_xsign_base_url(), 'https://xsign-demo.v2.appdeploy.ai')

    def test_current_appdeploy_url_is_preserved(self) -> None:
        with mock.patch.dict(os.environ, {'XSIGN_BASE_URL': 'https://xsign-demo.v2.appdeploy.ai'}, clear=False):
            self.assertEqual(xw.configured_xsign_base_url(), 'https://xsign-demo.v2.appdeploy.ai')


class RetryBehaviorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.sleeps: list[float] = []
        self._sleep_patch = mock.patch.object(xw, 'sleep_with_jitter', side_effect=self.sleeps.append)
        self._sleep_patch.start()
        self.addCleanup(self._sleep_patch.stop)

    def test_402_retries_then_succeeds(self) -> None:
        responses = [
            _FakeResponse(402, {'code': 'APP_TEMPORARILY_UNAVAILABLE'}),
            _FakeResponse(402, {'code': 'APP_TEMPORARILY_UNAVAILABLE'}),
            _FakeResponse(200, {'ok': True}),
        ]
        client = _client()
        with mock.patch.object(client.s, 'request', side_effect=responses) as req:
            status, data = client.request('POST', '/api/worker/heartbeat')
        self.assertEqual(status, 200)
        self.assertEqual(data, {'ok': True})
        self.assertEqual(req.call_count, 3)
        self.assertEqual(len(self.sleeps), 2)
        # Exponential backoff: delays grow (2s then 4s base).
        self.assertLessEqual(self.sleeps[0], self.sleeps[1])

    def test_402_exhaustion_raises_retryable(self) -> None:
        client = _client(max_retry_seconds=2.0)
        clock = iter([0.0] + [x * 0.5 for x in range(1, 30)])
        with mock.patch.object(client.s, 'request', return_value=_FakeResponse(402, {'code': 'APP_TEMPORARILY_UNAVAILABLE'})), \
             mock.patch.object(xw.time, 'monotonic', side_effect=lambda: next(clock)):
            with self.assertRaises(xw.RetryableAPIError) as ctx:
                client.request('POST', '/api/worker/heartbeat')
        self.assertEqual(ctx.exception.status_code, 402)

    def test_retry_budget_is_bounded(self) -> None:
        client = _client(max_retry_seconds=3.0)
        clock = iter([0.0] + [x * 0.4 for x in range(1, 40)])
        calls = {'n': 0}

        def _always_503(*_a: object, **_k: object) -> _FakeResponse:
            calls['n'] += 1
            return _FakeResponse(503, {'error': 'down'})

        with mock.patch.object(client.s, 'request', side_effect=_always_503), \
             mock.patch.object(xw.time, 'monotonic', side_effect=lambda: next(clock)):
            with self.assertRaises(xw.RetryableAPIError):
                client.request('GET', '/api/worker/signing-identity')
        self.assertGreaterEqual(calls['n'], 2)
        self.assertLessEqual(calls['n'], 12)

    def test_network_errors_are_retried(self) -> None:
        client = _client()
        attempts = [requests.ConnectionError('refused'), _FakeResponse(200, {'ok': 1})]
        with mock.patch.object(client.s, 'request', side_effect=attempts):
            status, data = client.request('GET', '/api/worker/signing-identity')
        self.assertEqual(status, 200)
        self.assertEqual(data['ok'], 1)
        self.assertEqual(len(self.sleeps), 1)

    def test_non_retryable_status_raises_immediately(self) -> None:
        client = _client()
        with mock.patch.object(client.s, 'request', return_value=_FakeResponse(403, {'error': 'forbidden'})) as req:
            with self.assertRaises(xw.WorkerError):
                client.request('POST', '/api/worker/heartbeat')
        self.assertEqual(req.call_count, 1)
        self.assertEqual(self.sleeps, [])

    def test_allow_statuses_bypasses_retry(self) -> None:
        client = _client()
        with mock.patch.object(client.s, 'request', return_value=_FakeResponse(503, {'error': 'later'})) as req:
            status, _ = client.request('GET', '/api/worker/signing-identity', allow_statuses=(503,))
        self.assertEqual(status, 503)
        self.assertEqual(req.call_count, 1)


class HeartbeatGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self._sleep_patch = mock.patch.object(xw, 'sleep_with_jitter', lambda _s: None)
        self._sleep_patch.start()
        self.addCleanup(self._sleep_patch.stop)
        self.summary_path = None

    def _run_worker_with(self, responses: list[_FakeResponse]) -> tuple[int, dict]:
        client = _client()
        args = types.SimpleNamespace(max_jobs=3, max_retry_seconds=5.0)
        with mock.patch.object(xw, 'XSignClient', return_value=client), \
             mock.patch.object(xw, 'AppleClient', autospec=True) as apple_cls, \
             mock.patch.object(client.s, 'request', side_effect=responses), \
             mock.patch.object(xw, 'write_github_summary'), \
             mock.patch.object(xw, 'check_fallback_secrets', return_value=['X']):
            apple_cls.return_value = mock.Mock()
            summary: dict = {}
            with mock.patch.object(xw, 'write_github_summary', side_effect=lambda s: summary.update(s)):
                code = xw.run_worker(args)
        return code, summary

    def test_failed_heartbeat_never_claims_a_job(self) -> None:
        client = _client(max_retry_seconds=2.0)
        args = types.SimpleNamespace(max_jobs=3, max_retry_seconds=2.0)
        claim_called = {'value': False}
        clock = iter([0.0] + [x * 0.5 for x in range(1, 40)])
        with mock.patch.object(xw, 'XSignClient', return_value=client), \
             mock.patch.object(xw, 'AppleClient', autospec=True), \
             mock.patch.object(client.s, 'request', return_value=_FakeResponse(402, {'code': 'APP_TEMPORARILY_UNAVAILABLE'})), \
             mock.patch.object(xw.time, 'monotonic', side_effect=lambda: next(clock)), \
             mock.patch.object(client, 'claim', side_effect=lambda: claim_called.update(value=True)), \
             mock.patch.object(xw, 'write_github_summary'), \
             mock.patch.object(xw, 'check_fallback_secrets', return_value=[]):
            code = xw.run_worker(args)
        self.assertEqual(code, 0, 'Outage should defer cleanly so the scheduler can retry later.')
        self.assertFalse(claim_called['value'], 'claim() must not run when heartbeat fails.')

    def test_deferred_job_is_not_marked_complete(self) -> None:
        client = _client()
        args = types.SimpleNamespace(max_jobs=3, max_retry_seconds=5.0)
        job = {'id': 'job-1', 'udid': 'u' * 40, 'filename': 'app.ipa'}
        process_effects = [xw.RetryableAPIError('API down', status_code=503)]
        completed: list[str] = []
        with mock.patch.object(xw, 'XSignClient', return_value=client), \
             mock.patch.object(xw, 'AppleClient', autospec=True), \
             mock.patch.object(client.s, 'request', return_value=_FakeResponse(200, {'ok': 1})), \
             mock.patch.object(client, 'claim', return_value=job), \
             mock.patch.object(xw, 'process_job', side_effect=process_effects), \
             mock.patch.object(client, 'complete', side_effect=lambda *a, **k: completed.append('x')), \
             mock.patch.object(client, 'fail', side_effect=lambda *a, **k: completed.append('fail')), \
             mock.patch.object(xw, 'write_github_summary'), \
             mock.patch.object(xw, 'check_fallback_secrets', return_value=[]):
            code = xw.run_worker(args)
        self.assertEqual(code, 0)
        self.assertEqual(completed, [], 'Deferred jobs must not call complete() or fail().')


class RedactionTests(unittest.TestCase):
    def test_registered_secret_is_scrubbed(self) -> None:
        redactor = xw._SecretRedactor()
        redactor.register('super-secret-value-123')
        self.assertEqual(redactor.scrub('token=super-secret-value-123'), 'token=***')

    def test_jwt_is_scrubbed(self) -> None:
        redactor = xw._SecretRedactor()
        jwt = '******'
        self.assertNotIn('eyJhbGci', redactor.scrub(f'got {jwt}'))

    def test_udid_and_long_hex_are_scrubbed(self) -> None:
        redactor = xw._SecretRedactor()
        udid = 'A' * 40
        token64 = 'b' * 64
        out = redactor.scrub(f'udid={udid} token={token64}')
        self.assertNotIn(udid, out)
        self.assertNotIn(token64, out)

    def test_jlog_never_prints_registered_secret(self) -> None:
        redactor = xw.REDACTOR
        redactor.register('sk-test-abcdef-123456')
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            xw.jlog('demo', detail='using sk-test-abcdef-123456 now')
        self.assertNotIn('sk-test-abcdef-123456', buf.getvalue())

    def test_request_error_message_is_scrubbed(self) -> None:
        client = _client()
        secret = 'hunter2-hunter2'
        xw.REDACTOR.register(secret)
        resp = _FakeResponse(403, {'error': f'denied for {secret}'})
        with mock.patch.object(client.s, 'request', return_value=resp):
            with self.assertRaises(xw.WorkerError) as ctx:
                client.request('GET', '/x')
        self.assertNotIn(secret, str(ctx.exception))


class HealthCheckTests(unittest.TestCase):
    def setUp(self) -> None:
        self._sleep_patch = mock.patch.object(xw, 'sleep_with_jitter', lambda _s: None)
        self._sleep_patch.start()
        self.addCleanup(self._sleep_patch.stop)

    def test_health_check_ok(self) -> None:
        client = _client()
        args = types.SimpleNamespace(max_retry_seconds=30.0)
        with mock.patch.object(xw, 'XSignClient', return_value=client), \
             mock.patch.object(client.s, 'request', return_value=_FakeResponse(200, {'ok': 1})):
            self.assertEqual(xw.health_check(args), 0)

    def test_health_check_degraded(self) -> None:
        client = _client(max_retry_seconds=1.0)
        args = types.SimpleNamespace(max_retry_seconds=1.0)
        with mock.patch.object(xw, 'XSignClient', return_value=client), \
             mock.patch.object(client.s, 'request', return_value=_FakeResponse(402, {'code': 'APP_TEMPORARILY_UNAVAILABLE'})):
            self.assertEqual(xw.health_check(args), 1)


class DryRunTests(unittest.TestCase):
    def setUp(self) -> None:
        self._sleep_patch = mock.patch.object(xw, 'sleep_with_jitter', lambda _s: None)
        self._sleep_patch.start()
        self.addCleanup(self._sleep_patch.stop)

    def test_dry_run_successful_job_is_not_completed(self) -> None:
        client = _client()
        args = types.SimpleNamespace(max_retry_seconds=30.0)
        job = {'id': 'job-dry', 'udid': 'c' * 40, 'filename': 'x.ipa', 'callbackUrl': ''}
        buf = io.StringIO()
        with mock.patch.object(xw, 'XSignClient', return_value=client), \
             mock.patch.object(client.s, 'request', return_value=_FakeResponse(200, {'ok': 1})), \
             mock.patch.object(client, 'claim', return_value=job), \
             mock.patch.object(client, 'complete') as complete_mock, \
             mock.patch.object(client, 'fail') as fail_mock, \
             contextlib.redirect_stdout(buf):
            code = xw.run_dry_run(args)
        self.assertEqual(code, 0)
        complete_mock.assert_not_called()
        fail_mock.assert_not_called()
        self.assertIn('"result": "deferred"', buf.getvalue())

    def test_dry_run_empty_queue(self) -> None:
        client = _client()
        args = types.SimpleNamespace(max_retry_seconds=30.0)
        buf = io.StringIO()
        with mock.patch.object(xw, 'XSignClient', return_value=client), \
             mock.patch.object(client.s, 'request', return_value=_FakeResponse(200, {'ok': 1})), \
             mock.patch.object(client, 'claim', return_value=None), \
             contextlib.redirect_stdout(buf):
            code = xw.run_dry_run(args)
        self.assertEqual(code, 0)
        self.assertIn('queue_empty', buf.getvalue())


class FallbackSecretTests(unittest.TestCase):
    def test_missing_secrets_are_reported_individually(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True):
            missing = xw.check_fallback_secrets()
        self.assertEqual(missing, list(xw.FALLBACK_REQUIRED_ENV_VARS))

    def test_partial_configuration_lists_only_missing(self) -> None:
        env = {'APPLE_ISSUER_ID': 'x', 'SIGNING_API_BASE': 'https://api.example.test'}
        with mock.patch.dict(os.environ, env, clear=True):
            missing = xw.check_fallback_secrets()
        self.assertNotIn('APPLE_ISSUER_ID', missing)
        self.assertIn('APPLE_P12_BASE64', missing)
        self.assertIn('SIGNING_API_TOKEN', missing)

    def test_fallback_never_fakes_success(self) -> None:
        buf = io.StringIO()
        with mock.patch.dict(os.environ, {}, clear=True), contextlib.redirect_stdout(buf):
            code = xw.run_fallback_direct_signing()
        self.assertEqual(code, 2)
        out = buf.getvalue()
        self.assertIn('missing', out.lower())
        self.assertNotIn('signed successfully', out.lower())


if __name__ == '__main__':
    unittest.main()
