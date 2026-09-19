#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import plistlib
import random
import re
import secrets as pysecrets
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import requests

CHUNK_SIZE = 384 * 1024
DEFAULT_BUNDLE_PREFIX = 'com.moha700m.xsign'
WORKER_VERSION = '3.3.0'
DEFAULT_XSIGN_BASE_URL = 'https://api-v2.appdeploy.ai/app/xsign-0xcfp9'
JOB_LOG_LIMIT = 8

# Transient XSign infrastructure statuses. A 402 carrying the code
# APP_TEMPORARILY_UNAVAILABLE means the signing engine is temporarily down; it
# is NOT a payment rejection of the customer job. Retry with backoff instead of
# hot-looping or marking customer orders as failed.
RETRYABLE_STATUSES = frozenset({402, 408, 429, 500, 502, 503, 504})
RETRY_BASE_DELAY_SECONDS = 2.0
RETRY_MAX_DELAY_SECONDS = 60.0
RETRY_MAX_DURATION_SECONDS = 180.0
HEALTH_RETRY_MAX_DURATION_SECONDS = 30.0


class WorkerError(RuntimeError):
    pass


class RetryableAPIError(WorkerError):
    """A transient XSign API failure that is safe to retry with backoff."""

    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class DeferJobs(WorkerError):
    """XSign is unavailable right now; leave every queued job pending."""

    def __init__(self, message: str) -> None:
        super().__init__(message)


REDACTED = '***'


class _SecretRedactor:
    """Best-effort scrubber so secrets never reach CI logs or status messages."""

    def __init__(self) -> None:
        self._values: list[str] = []

    def register(self, value: Any) -> None:
        text = str(value or '').strip()
        if len(text) >= 4 and text not in self._values:
            self._values.append(text)

    def scrub(self, value: Any) -> str:
        text = str(value)
        for secret in self._values:
            if secret and secret in text:
                text = text.replace(secret, REDACTED)
        text = re.sub(
            r'eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}',
            REDACTED,
            text,
        )
        text = re.sub(
            r'(ACTIONS_ID_TOKEN_REQUEST_TOKEN=)\S+',
            rf'\1{REDACTED}',
            text,
        )
        text = re.sub(r'\b[0-9A-Fa-f]{40}\b', REDACTED, text)
        text = re.sub(r'\b[0-9a-fA-F]{64}\b', REDACTED, text)
        text = re.sub(
            r'\b[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\b',
            REDACTED,
            text,
        )
        return text

    def scrub_structure(self, value: Any) -> Any:
        if isinstance(value, dict):
            return {key: self.scrub_structure(item) for key, item in value.items()}
        if isinstance(value, list):
            return [self.scrub_structure(item) for item in value]
        if isinstance(value, str):
            return self.scrub(value)
        return value


REDACTOR = _SecretRedactor()


def jlog(event: str, **fields: Any) -> None:
    """Emit one structured, sanitized log line."""
    record: dict[str, Any] = {'ts': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), 'event': event}
    record.update(fields)
    print(json.dumps(REDACTOR.scrub_structure(record), ensure_ascii=False, default=str), flush=True)


def required_env(name: str) -> str:
    value = os.environ.get(name, '').strip()
    if not value:
        raise WorkerError(f'Missing required environment value: {name}')
    return value


def configured_xsign_base_url() -> str:
    base = os.environ.get('XSIGN_BASE_URL', '').strip()
    if not base:
        jlog(
            'config_default_base_url',
            message='XSIGN_BASE_URL is not configured; using the built-in default endpoint.',
        )
        base = DEFAULT_XSIGN_BASE_URL
    return base.rstrip('/')


def sleep_with_jitter(delay: float) -> None:
    jitter = min(delay * 0.25, 5.0)
    time.sleep(delay + random.uniform(0.0, jitter))


def command_preview(args: list[str]) -> str:
    redacted: list[str] = []
    hide_next = False
    sensitive_flags = {'-p', '-P', '-k', '-passin', '-passout'}
    for arg in args:
        if hide_next:
            redacted.append('***')
            hide_next = False
            continue
        if '=' in arg and arg.split('=', 1)[0] in sensitive_flags:
            redacted.append(f'{arg.split("=", 1)[0]}=***')
            continue
        redacted.append(arg)
        if arg in sensitive_flags:
            hide_next = True
    return ' '.join(redacted[:5])


def run(args: list[str], *, cwd: Path | None = None, capture: bool = True) -> str:
    proc = subprocess.run(
        args,
        cwd=str(cwd) if cwd else None,
        check=False,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
    )
    if proc.returncode != 0:
        stderr = (proc.stderr or '').strip()
        stdout = (proc.stdout or '').strip()
        detail = stderr or stdout or f'exit code {proc.returncode}'
        raise WorkerError(f'{command_preview(args)} failed: {detail[:1800]}')
    return (proc.stdout or '').strip()


def github_oidc_token() -> str:
    request_url = required_env('ACTIONS_ID_TOKEN_REQUEST_URL')
    request_token = required_env('ACTIONS_ID_TOKEN_REQUEST_TOKEN')
    separator = '&' if '?' in request_url else '?'
    url = f'{request_url}{separator}audience={urllib.parse.quote("xsign-worker")}'
    req = urllib.request.Request(
        url,
        headers={'Authorization': f'Bearer {request_token}', 'Accept': 'application/json'},
    )
    with urllib.request.urlopen(req, timeout=30) as response:
        payload = json.loads(response.read().decode('utf-8'))
    token = str(payload.get('value', '')).strip()
    if not token:
        raise WorkerError('GitHub Actions did not return an OIDC token.')
    REDACTOR.register(token)
    return token


def _log_response_excerpt(response: requests.Response) -> str:
    text = (response.text or '').strip()
    if len(text) > 200:
        text = text[:200] + '...'
    return text


class XSignClient:
    def __init__(self, max_retry_seconds: float = RETRY_MAX_DURATION_SECONDS) -> None:
        self.base = configured_xsign_base_url()
        self.max_retry_seconds = max(1.0, float(max_retry_seconds))
        self.request_count = 0
        self.s = requests.Session()
        headers = {
            'Accept': 'application/json',
            'User-Agent': f'XSign-GitHub-Worker/{WORKER_VERSION}',
        }
        if os.environ.get('ACTIONS_ID_TOKEN_REQUEST_URL') and os.environ.get('ACTIONS_ID_TOKEN_REQUEST_TOKEN'):
            headers['Authorization'] = f'Bearer {github_oidc_token()}'
        else:
            worker_secret = os.environ.get('XSIGN_WORKER_SECRET', '').strip()
            if worker_secret:
                REDACTOR.register(worker_secret)
                headers['X-XSign-Worker-Secret'] = worker_secret
        self.s.headers.update(headers)

    def _decode(self, response: requests.Response) -> dict[str, Any]:
        try:
            data = response.json()
        except Exception:
            data = {'error': response.text[:500]}
        if not isinstance(data, dict):
            return {'data': data}
        return data

    def request(
        self,
        method: str,
        path: str,
        *,
        json_body: dict[str, Any] | None = None,
        allow_statuses: tuple[int, ...] = (),
    ) -> tuple[int, dict[str, Any]]:
        attempt = 0
        started = time.monotonic()
        method = method.upper()
        last_response: requests.Response | None = None
        while True:
            attempt += 1
            status_code: int | None = None
            data: dict[str, Any] = {}
            retry_reason: str | None = None
            last_response = None
            try:
                last_response = self.s.request(method, f'{self.base}{path}', json=json_body, timeout=120)
                status_code = last_response.status_code
                data = self._decode(last_response)
                if status_code in RETRYABLE_STATUSES and status_code not in allow_statuses:
                    retry_reason = f'http_{status_code}'
            except requests.RequestException as exc:
                retry_reason = f'network_{exc.__class__.__name__.lower()}'
                jlog(
                    'http_attempt',
                    attempt=attempt,
                    method=method,
                    path=path,
                    error=exc.__class__.__name__,
                )
            self.request_count += 1
            if retry_reason is None:
                jlog(
                    'http_request',
                    attempt=attempt,
                    method=method,
                    path=path,
                    status=status_code,
                )
                if status_code is not None and status_code >= 400 and status_code not in allow_statuses:
                    raise WorkerError(f'XSign {method} {path} -> {status_code}: {REDACTOR.scrub(data)}')
                return (status_code if status_code is not None else 0), data
            elapsed = time.monotonic() - started
            if elapsed >= self.max_retry_seconds:
                jlog(
                    'http_retry_exhausted',
                    attempts=attempt,
                    elapsed_seconds=round(elapsed, 1),
                    method=method,
                    path=path,
                    reason=retry_reason,
                    status=status_code,
                )
                if retry_reason.startswith('network_'):
                    raise RetryableAPIError(
                        f'XSign {method} {path} unreachable after {attempt} attempts '
                        f'({retry_reason}) over {elapsed:.0f}s'
                    ) from None
                raise RetryableAPIError(
                    f'XSign {method} {path} -> {status_code} persisted for {elapsed:.0f}s '
                    f'across {attempt} attempts: {REDACTOR.scrub(data)}',
                    status_code=status_code,
                )
            remaining = self.max_retry_seconds - elapsed
            # Clamp the exponent before 2**n so long outages cannot overflow.
            backoff = RETRY_BASE_DELAY_SECONDS * (2 ** min(attempt - 1, 16))
            delay = min(backoff, RETRY_MAX_DELAY_SECONDS, remaining)
            jlog(
                'http_retry',
                attempt=attempt,
                delay_seconds=round(delay, 1),
                method=method,
                path=path,
                reason=retry_reason,
                status=status_code,
                response_excerpt=_log_response_excerpt(last_response) if last_response is not None else '',
            )
            sleep_with_jitter(delay)

    def heartbeat(self) -> None:
        self.request('POST', '/api/worker/heartbeat', json_body={'workerId': 'github-macos', 'version': WORKER_VERSION})

    def health_check(self) -> None:
        """Readiness probe: verifies the API and Apple credentials without claiming a job."""
        self.request('POST', '/api/worker/heartbeat', json_body={'workerId': 'github-macos-healthcheck', 'version': WORKER_VERSION})
        self.apple('ping')

    def claim(self) -> dict[str, Any] | None:
        _, data = self.request('POST', '/api/worker/claim', json_body={})
        job = data.get('job')
        return job if isinstance(job, dict) else None

    def status(self, job_id: str, status: str, message: str) -> None:
        self.request('POST', f'/api/worker/jobs/{job_id}/status', json_body={'status': status, 'message': message})

    def input_chunk(self, job_id: str, index: int) -> bytes:
        _, data = self.request('GET', f'/api/worker/jobs/{job_id}/input/{index}')
        return base64.b64decode(str(data['content']), validate=True)

    def output_chunk(self, job_id: str, index: int, content: bytes) -> None:
        self.request(
            'POST',
            f'/api/worker/jobs/{job_id}/output/chunk',
            json_body={'index': index, 'content': base64.b64encode(content).decode('ascii')},
        )

    def complete(self, job_id: str, chunk_count: int, filename: str, expiration: str | None) -> None:
        payload: dict[str, Any] = {'chunkCount': chunk_count, 'filename': filename}
        if expiration:
            payload['expirationDate'] = expiration
        self.request('POST', f'/api/worker/jobs/{job_id}/complete', json_body=payload)

    def portal_complete(self, job_id: str, filename: str, expiration: str | None) -> None:
        payload: dict[str, Any] = {'filename': filename}
        if expiration:
            payload['expirationDate'] = expiration
        self.request('POST', f'/api/worker/jobs/{job_id}/portal-complete', json_body=payload)

    def fail(self, job_id: str, message: str) -> None:
        try:
            self.request('POST', f'/api/worker/jobs/{job_id}/fail', json_body={'message': message[:500]})
        except Exception as exc:
            print(f'Could not report failure to XSign: {exc}')

    def apple(self, action: str, **kwargs: Any) -> dict[str, Any]:
        _, data = self.request('POST', '/api/worker/apple', json_body={'action': action, **kwargs})
        return data

    def get_signing_identity(self) -> dict[str, str] | None:
        # 404 = no identity stored yet. Retryable statuses (e.g. 503 during an
        # outage) deliberately retry with backoff so an identity fetch cannot
        # silently bootstrap a duplicate certificate mid-outage.
        status, data = self.request('GET', '/api/worker/signing-identity', allow_statuses=(404,))
        if status == 404:
            return None
        p12_b64 = str(data.get('p12B64', ''))
        password = str(data.get('password', ''))
        if not p12_b64:
            return None
        return {'p12B64': p12_b64, 'password': password}

    def save_signing_identity(self, p12_b64: str, password: str) -> None:
        self.request(
            'POST',
            '/api/worker/signing-identity',
            json_body={'p12B64': p12_b64, 'password': password},
        )


class AppleClient:
    def __init__(self, xs: XSignClient) -> None:
        self.xs = xs

    def _retry_transient(self, action: str, **kwargs: Any) -> dict[str, Any]:
        # Apple occasionally returns 5xx responses while creating/registering
        # resources. These ensure operations are idempotent, so retry them with
        # backoff instead of permanently failing the customer's signing job.
        for attempt in range(4):
            try:
                return self.xs.apple(action, **kwargs)
            except RetryableAPIError:
                # The XSign API itself is degraded; defer instead of failing the job.
                raise
            except WorkerError as exc:
                if attempt >= 3 or not re.search(r'-> (500|502|503|504)\b', str(exc)):
                    raise
                delay = 5 * (2 ** attempt)
                jlog(
                    'apple_retry',
                    action=action,
                    attempt=attempt + 1,
                    delay_seconds=delay,
                )
                time.sleep(delay)
        raise WorkerError(f'Apple {action} retry loop exhausted.')

    def create_distribution_certificate(self, csr_content: str) -> dict[str, Any]:
        return self.xs.apple('certificate.create', csrContent=csr_content)

    def certificate_id_for_serial(self, serial: str) -> str:
        return str(self._retry_transient('certificate.lookup', serial=serial)['id'])

    def get_or_register_device(self, udid: str, name: str) -> str:
        return str(self._retry_transient('device.ensure', udid=udid, name=name)['id'])

    def get_or_create_bundle_id(self, bundle_id: str, display_name: str) -> str:
        return str(self._retry_transient('bundle.ensure', identifier=bundle_id, name=display_name)['id'])

    def ensure_capability(self, bundle_resource_id: str, capability_type: str) -> None:
        self._retry_transient(
            'capability.ensure',
            bundleId=bundle_resource_id,
            capabilityType=capability_type,
        )

    def get_or_create_profile(
        self,
        name: str,
        bundle_resource: str,
        device_resource: str,
        certificate_resource: str,
    ) -> tuple[bytes, str | None]:
        data = self._retry_transient(
            'profile.ensure',
            name=name,
            bundleId=bundle_resource,
            deviceId=device_resource,
            certificateId=certificate_resource,
        )
        content = str(data.get('profileContent', ''))
        if not content:
            raise WorkerError('Apple did not return provisioning profile content.')
        return base64.b64decode(content), data.get('expirationDate')


def safe_extract(ipa: Path, dest: Path) -> None:
    with zipfile.ZipFile(ipa) as zf:
        root = dest.resolve()
        total = 0
        for info in zf.infolist():
            total += info.file_size
            if total > 2 * 1024 * 1024 * 1024:
                raise WorkerError('IPA expands beyond the 2 GB safety limit.')
            target = (dest / info.filename).resolve()
            if target != root and root not in target.parents:
                raise WorkerError('IPA contains an unsafe path traversal entry.')
        bad = zf.testzip()
        if bad:
            raise WorkerError(f'IPA ZIP integrity check failed at {bad}.')
        zf.extractall(dest)


def slug(value: str, fallback: str = 'app') -> str:
    cleaned = re.sub(r'[^a-z0-9-]+', '-', value.lower()).strip('-')
    cleaned = re.sub(r'-+', '-', cleaned)
    if not cleaned:
        cleaned = fallback
    if cleaned[0].isdigit():
        cleaned = f'a{cleaned}'
    return cleaned[:45]


@dataclass
class BundleSpec:
    path: Path
    info_path: Path
    original_id: str
    new_id: str
    display_name: str
    is_extension: bool
    needs_push: bool = False
    bundle_resource_id: str | None = None
    profile_path: Path | None = None
    expiration: str | None = None


def read_info(bundle: Path) -> tuple[Path, dict[str, Any]]:
    info_path = bundle / 'Info.plist'
    if not info_path.exists():
        raise WorkerError(f'Info.plist is missing from {bundle.name}.')
    with info_path.open('rb') as f:
        info = plistlib.load(f)
    return info_path, info


def write_info(path: Path, info: dict[str, Any]) -> None:
    with path.open('wb') as f:
        plistlib.dump(info, f, fmt=plistlib.FMT_BINARY, sort_keys=False)


def inspect_and_remap(ipa: Path, work: Path, bundle_prefix: str) -> tuple[Path, list[BundleSpec]]:
    unpacked = work / 'unpacked'
    unpacked.mkdir(parents=True, exist_ok=True)
    safe_extract(ipa, unpacked)

    apps = list((unpacked / 'Payload').glob('*.app'))
    if len(apps) != 1:
        raise WorkerError('IPA must contain exactly one top-level Payload/*.app.')
    app = apps[0]
    if list(app.glob('Watch/*.app')):
        raise WorkerError('Watch app bundles are not supported yet.')

    main_info_path, main_info = read_info(app)
    original_main = str(main_info.get('CFBundleIdentifier', '')).strip()
    if not original_main:
        raise WorkerError('Main app CFBundleIdentifier is missing.')
    display_name = str(main_info.get('CFBundleDisplayName') or main_info.get('CFBundleName') or app.stem).strip()

    prefix = re.sub(r'[^A-Za-z0-9.-]+', '', bundle_prefix.strip()).strip('.')
    if prefix.count('.') < 1:
        raise WorkerError('APPLE_BUNDLE_PREFIX must be a reverse-DNS prefix such as com.example.xsign.')
    new_main = original_main if original_main.startswith(prefix + '.') else f'{prefix}.{slug(original_main.split(".")[-1] or app.stem, "app")}'

    extension_dirs = sorted(app.glob('PlugIns/*.appex'))
    has_notification_service = False
    ext_infos: list[tuple[Path, Path, dict[str, Any], str, str]] = []
    for ext in extension_dirs:
        info_path, info = read_info(ext)
        original_id = str(info.get('CFBundleIdentifier', '')).strip()
        if not original_id:
            raise WorkerError(f'{ext.name} CFBundleIdentifier is missing.')
        if original_id.startswith(original_main + '.'):
            suffix = original_id[len(original_main) + 1:]
        else:
            suffix = ext.stem
        suffix = '.'.join(slug(part, 'ext') for part in suffix.split('.'))
        new_id = f'{new_main}.{suffix}'
        point = str((info.get('NSExtension') or {}).get('NSExtensionPointIdentifier', ''))
        has_notification_service = has_notification_service or point == 'com.apple.usernotifications.service'
        ext_infos.append((ext, info_path, info, original_id, new_id))

    background_modes = main_info.get('UIBackgroundModes') or []
    main_needs_push = has_notification_service or 'remote-notification' in background_modes
    main_info['CFBundleIdentifier'] = new_main
    write_info(main_info_path, main_info)

    specs = [BundleSpec(app, main_info_path, original_main, new_main, display_name, False, main_needs_push)]
    mapping = {original_main: new_main}
    for ext, info_path, info, original_id, new_id in ext_infos:
        info['CFBundleIdentifier'] = new_id
        if info.get('WKCompanionAppBundleIdentifier') in mapping:
            info['WKCompanionAppBundleIdentifier'] = mapping[info['WKCompanionAppBundleIdentifier']]
        write_info(info_path, info)
        mapping[original_id] = new_id
        ext_name = str(info.get('CFBundleDisplayName') or info.get('CFBundleName') or ext.stem).strip()
        specs.append(BundleSpec(ext, info_path, original_id, new_id, ext_name, True, False))

    return app, specs


def write_b64_file(value: str, output: Path, label: str) -> None:
    try:
        output.write_bytes(base64.b64decode(value, validate=True))
    except Exception as exc:
        raise WorkerError(f'{label} is not valid base64.') from exc


def create_signing_identity(xs: XSignClient, apple: AppleClient, p12: Path, work: Path) -> str:
    jlog('identity_create', message='Creating a macOS-compatible XSign signing identity through Apple API.')
    private_key = work / 'distribution-private.pem'
    csr = work / 'distribution.csr'
    cert_der = work / 'distribution.cer'
    cert_pem = work / 'distribution.pem'
    password = pysecrets.token_hex(36)
    REDACTOR.register(password)

    run(['openssl', 'genrsa', '-out', str(private_key), '2048'])
    run([
        'openssl', 'req', '-new', '-key', str(private_key), '-out', str(csr),
        '-subj', '/CN=XSign Distribution/O=XSign/C=SA',
    ])
    created = apple.create_distribution_certificate(csr.read_text(encoding='utf-8'))
    cert_content = str(created.get('certificateContent', ''))
    if not cert_content:
        raise WorkerError('Apple Distribution certificate creation returned no certificate content.')
    write_b64_file(cert_content, cert_der, 'Apple certificate content')
    run(['openssl', 'x509', '-inform', 'DER', '-in', str(cert_der), '-out', str(cert_pem)])
    run([
        'openssl', 'pkcs12', '-legacy', '-export',
        '-inkey', str(private_key), '-in', str(cert_pem),
        '-out', str(p12), '-passout', f'pass:{password}',
        '-name', 'XSign Apple Distribution',
        '-macalg', 'sha1',
        '-keypbe', 'PBE-SHA1-3DES',
        '-certpbe', 'PBE-SHA1-3DES',
    ])
    p12_b64 = base64.b64encode(p12.read_bytes()).decode('ascii')
    xs.save_signing_identity(p12_b64, password)
    jlog('identity_persisted', message='Persisted new XSign signing identity in encrypted AppDeploy storage.')
    return password


def bootstrap_signing_identity(
    xs: XSignClient,
    apple: AppleClient,
    p12: Path,
    work: Path,
) -> tuple[str, bool]:
    existing = xs.get_signing_identity()
    if existing:
        REDACTOR.register(existing['password'])
        write_b64_file(existing['p12B64'], p12, 'Stored signing identity')
        return existing['password'], True
    return create_signing_identity(xs, apple, p12, work), False


def rewrap_signing_identity(xs: XSignClient, p12: Path, password: str, work: Path) -> str:
    raw_key = work / 'persisted-private.raw.pem'
    raw_cert = work / 'persisted-cert.raw.pem'
    clean_key = work / 'persisted-private.pem'
    clean_cert = work / 'persisted-cert.pem'
    compatible_p12 = work / 'distribution-compatible.p12'

    run([
        'openssl', 'pkcs12', '-in', str(p12), '-nocerts', '-nodes',
        '-passin', f'pass:{password}', '-out', str(raw_key),
    ])
    run([
        'openssl', 'pkcs12', '-in', str(p12), '-clcerts', '-nokeys',
        '-passin', f'pass:{password}', '-out', str(raw_cert),
    ])
    run(['openssl', 'pkey', '-in', str(raw_key), '-out', str(clean_key)])
    run(['openssl', 'x509', '-in', str(raw_cert), '-out', str(clean_cert)])

    new_password = pysecrets.token_hex(36)
    REDACTOR.register(new_password)
    run([
        'openssl', 'pkcs12', '-legacy', '-export',
        '-inkey', str(clean_key), '-in', str(clean_cert),
        '-out', str(compatible_p12), '-passout', f'pass:{new_password}',
        '-name', 'XSign Apple Distribution',
        '-macalg', 'sha1',
        '-keypbe', 'PBE-SHA1-3DES',
        '-certpbe', 'PBE-SHA1-3DES',
    ])
    shutil.copy2(compatible_p12, p12)
    p12_b64 = base64.b64encode(p12.read_bytes()).decode('ascii')
    xs.save_signing_identity(p12_b64, new_password)
    jlog('identity_rewrapped', message='Rewrapped the persisted signing identity for macOS keychain compatibility.')
    return new_password


def import_p12(p12: Path, password: str, work: Path) -> tuple[Path, str, str]:
    keychain = work / f'{work.name}.keychain-db'
    keychain_password = pysecrets.token_urlsafe(32)
    run(['security', 'create-keychain', '-p', keychain_password, str(keychain)])
    run(['security', 'set-keychain-settings', '-lut', '21600', str(keychain)])
    run(['security', 'unlock-keychain', '-p', keychain_password, str(keychain)])
    # codesign needs both the temporary identity keychain and Apple's
    # intermediate/system keychains (for example WWDR). Preserve the existing
    # search list instead of replacing it with an isolated keychain.
    existing = run(['security', 'list-keychains'])
    search_keychains = [str(keychain)]
    search_keychains.extend(re.findall(r'"([^"]+)"', existing))
    for system_keychain in (
        '/Library/Keychains/System.keychain',
        '/System/Library/Keychains/SystemRootCertificates.keychain',
    ):
        if Path(system_keychain).exists() and system_keychain not in search_keychains:
            search_keychains.append(system_keychain)
    run(['security', 'list-keychains', '-d', 'user', '-s', *search_keychains])
    run(['security', 'default-keychain', '-d', 'user', '-s', str(keychain)])
    run(['security', 'import', str(p12), '-k', str(keychain), '-P', password, '-T', '/usr/bin/codesign', '-T', '/usr/bin/security'])
    run(['security', 'set-key-partition-list', '-S', 'apple-tool:,apple:,codesign:', '-s', '-k', keychain_password, str(keychain)])
    identities = run(['security', 'find-identity', '-v', '-p', 'codesigning', str(keychain)])
    match = re.search(r'\b([0-9A-F]{40})\b', identities)
    if not match:
        raise WorkerError('No Apple code-signing identity was found in the persisted PKCS#12 identity.')
    identity = match.group(1)

    cert_pem = work / 'distribution-cert.pem'
    run(['openssl', 'pkcs12', '-in', str(p12), '-clcerts', '-nokeys', '-passin', f'pass:{password}', '-out', str(cert_pem)])
    serial_line = run(['openssl', 'x509', '-in', str(cert_pem), '-noout', '-serial'])
    serial = serial_line.split('=', 1)[-1].strip().upper()
    return keychain, identity, serial


def profile_entitlements(profile: Path, output: Path) -> tuple[Path, str | None]:
    decoded = output.with_suffix('.decoded.plist')
    with decoded.open('wb') as out:
        proc = subprocess.run(['security', 'cms', '-D', '-i', str(profile)], stdout=out, stderr=subprocess.PIPE)
    if proc.returncode != 0:
        raise WorkerError(f"Unable to decode provisioning profile: {proc.stderr.decode(errors='ignore')[:800]}")
    with decoded.open('rb') as f:
        profile_plist = plistlib.load(f)
    entitlements = profile_plist.get('Entitlements') or {}
    entitlements_path = output.with_suffix('.entitlements.plist')
    with entitlements_path.open('wb') as f:
        plistlib.dump(entitlements, f, fmt=plistlib.FMT_XML)
    expiration = profile_plist.get('ExpirationDate')
    expiration_iso = expiration.isoformat() if hasattr(expiration, 'isoformat') else None
    return entitlements_path, expiration_iso


def strip_macho_signature(target: Path) -> bool:
    """Remove malformed LC_CODE_SIGNATURE commands before Apple's codesign runs."""
    try:
        import lief
    except Exception:
        return False
    try:
        parsed = lief.MachO.parse(str(target), config=lief.MachO.ParserConfig.deep)
        if isinstance(parsed, lief.MachO.FatBinary):
            binaries = [parsed.at(index) for index in range(parsed.size)]
        else:
            binaries = [parsed]
        changed = False
        for binary in binaries:
            if binary.has_code_signature:
                binary.remove_signature()
                changed = True
        if not changed:
            return False
        mode = target.stat().st_mode
        temporary = target.with_name(f'.{target.name}.unsigned')
        if temporary.exists():
            temporary.unlink()
        parsed.write(str(temporary))
        temporary.chmod(mode)
        os.replace(temporary, target)
        return True
    except Exception as exc:
        print(f'Mach-O signature cleanup skipped for {target.name}: {str(exc)[:300]}')
        return False


def remove_existing_signature(target: Path) -> None:
    # Existing signatures can contain requirements/entitlements from the original
    # developer team. Remove them before applying the new profile and identity.
    resolved = target.resolve()
    macho_target = resolved
    if resolved.is_dir():
        try:
            _, bundle_info = read_info(resolved)
            executable_name = str(bundle_info.get('CFBundleExecutable') or '').strip()
            if executable_name:
                for candidate in (
                    resolved / executable_name,
                    resolved / 'Versions' / 'Current' / executable_name,
                    resolved / 'Versions' / 'A' / executable_name,
                ):
                    if candidate.exists() and candidate.is_file():
                        macho_target = candidate.resolve()
                        break
        except Exception:
            pass
    strip_macho_signature(macho_target)
    removed = subprocess.run(
        ['codesign', '--remove-signature', str(resolved)],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    detail = (removed.stderr or removed.stdout or '').strip()
    if removed.returncode != 0 and detail and 'not signed' not in detail.lower():
        print(f'Existing signature cleanup warning for {target.name}: {detail[:300]}')
    signature = resolved / '_CodeSignature'
    if signature.exists():
        shutil.rmtree(signature)


def framework_executable(framework: Path) -> Path | None:
    info_path = framework / 'Info.plist'
    executable_name = ''
    if info_path.exists():
        try:
            _, info = read_info(framework)
            executable_name = str(info.get('CFBundleExecutable') or '').strip()
        except Exception:
            executable_name = ''
    candidates: list[Path] = []
    if executable_name:
        candidates.extend([
            framework / executable_name,
            framework / 'Versions' / 'Current' / executable_name,
            framework / 'Versions' / 'A' / executable_name,
        ])
    for candidate in candidates:
        if candidate.exists() and candidate.is_file():
            return candidate.resolve()
    return None


def sign_target(target: Path, identity: str, keychain: Path) -> None:
    target = target.resolve()
    remove_existing_signature(target)
    run([
        'codesign', '--force', '--sign', identity, '--keychain', str(keychain), '--timestamp=none',
        str(target),
    ])


def sign_code_objects(bundle: Path, identity: str, keychain: Path) -> None:
    targets: list[Path] = []
    for framework_dir in bundle.rglob('*.framework'):
        if not any(part.endswith('.appex') for part in framework_dir.parts):
            targets.append(framework_dir)
    for dylib in bundle.rglob('*.dylib'):
        if not any(part.endswith('.appex') for part in dylib.parts):
            targets.append(dylib)
    for target in sorted(set(targets), key=lambda p: len(p.parts), reverse=True):
        try:
            sign_target(target, identity, keychain)
        except WorkerError as exc:
            executable = framework_executable(target) if target.suffix == '.framework' else None
            if executable is None:
                raise
            print(f'Framework bundle signing failed for {target.name}; signing its executable instead ({exc}).')
            sign_target(executable, identity, keychain)


def sign_bundle(spec: BundleSpec, identity: str, keychain: Path, entitlements: Path) -> None:
    sign_code_objects(spec.path, identity, keychain)
    remove_existing_signature(spec.path)
    run([
        'codesign', '--force', '--sign', identity, '--keychain', str(keychain), '--timestamp=none',
        '--entitlements', str(entitlements), str(spec.path),
    ])
    run(['codesign', '--verify', '--strict', '--verbose=2', str(spec.path)])


def repack(unpacked: Path, output: Path) -> None:
    payload = unpacked / 'Payload'
    if output.exists():
        output.unlink()
    run(['ditto', '-c', '-k', '--sequesterRsrc', '--keepParent', str(payload), str(output)])
    if not zipfile.is_zipfile(output):
        raise WorkerError('Signed output is not a valid ZIP/IPA.')
    with zipfile.ZipFile(output) as zf:
        bad = zf.testzip()
        if bad:
            raise WorkerError(f'Signed IPA ZIP integrity check failed at {bad}.')


DEFAULT_PORTAL_HOST = 'xmod-store-mohammed.moha702m.chatgpt.site'
PORTAL_HOST = os.environ.get('XSIGN_PORTAL_HOST', '').strip() or DEFAULT_PORTAL_HOST
MAX_PORTAL_IPA_SIZE = 200 * 1024 * 1024


def validated_portal_url(value: str, kind: str) -> str:
    parsed = urllib.parse.urlparse(value)
    pattern = rf'^/api/signing/{kind}/[0-9a-f-]{{36}}$'
    if (
        parsed.scheme != 'https'
        or parsed.netloc != PORTAL_HOST
        or parsed.params
        or parsed.query
        or parsed.fragment
        or not re.fullmatch(pattern, parsed.path, re.IGNORECASE)
    ):
        raise WorkerError(f'Invalid portal {kind} URL.')
    return urllib.parse.urlunparse(parsed)


def portal_token(job: dict[str, Any]) -> str:
    token = str(job.get('signingToken') or '').strip()
    if not re.fullmatch(r'[0-9a-f]{64}', token, re.IGNORECASE):
        raise WorkerError('Portal signing token is invalid.')
    return token


def download_input(client: XSignClient, job: dict[str, Any], output: Path) -> None:
    source_url = str(job.get('sourceUrl') or '').strip()
    if source_url:
        url = validated_portal_url(source_url, 'source')
        expected_size = int(job.get('size') or 0)
        if expected_size < 1 or expected_size > MAX_PORTAL_IPA_SIZE:
            raise WorkerError('Portal IPA size is outside the allowed range.')
        with requests.get(
            url,
            headers={
                'X-Signing-Token': portal_token(job),
                'User-Agent': f'XSign-GitHub-Worker/{WORKER_VERSION}',
            },
            stream=True,
            timeout=(30, 900),
            allow_redirects=False,
        ) as response:
            if response.status_code != 200:
                raise WorkerError(f'Portal IPA download failed ({response.status_code}).')
            declared = int(response.headers.get('Content-Length') or 0)
            if declared and declared != expected_size:
                raise WorkerError('Portal IPA Content-Length does not match the job.')
            total = 0
            with output.open('wb') as f:
                for chunk in response.iter_content(1024 * 1024):
                    if not chunk:
                        continue
                    total += len(chunk)
                    if total > expected_size or total > MAX_PORTAL_IPA_SIZE:
                        raise WorkerError('Portal IPA exceeded the declared size.')
                    f.write(chunk)
            if total != expected_size:
                raise WorkerError('Portal IPA download was incomplete.')
        return

    with output.open('wb') as f:
        for index in range(int(job['chunkCount'])):
            f.write(client.input_chunk(job['id'], index))


def upload_portal_output(
    job: dict[str, Any],
    ipa: Path,
    app: Path,
    main_spec: BundleSpec,
    filename: str,
) -> None:
    callback_url = validated_portal_url(str(job.get('callbackUrl') or '').strip(), 'callback')
    _, info = read_info(app)
    size = ipa.stat().st_size
    if size < 1 or size > MAX_PORTAL_IPA_SIZE:
        raise WorkerError('Signed portal IPA size is outside the allowed range.')
    digest = hashlib.sha256()
    with ipa.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    expiration = str(main_spec.expiration or '').strip()
    if not expiration:
        raise WorkerError('Provisioning profile expiration is missing.')
    display_name = str(info.get('CFBundleDisplayName') or info.get('CFBundleName') or 'XMOD').strip()
    if not display_name.isascii():
        display_name = 'XMOD'
    headers = {
        'Content-Type': 'application/octet-stream',
        'Content-Length': str(size),
        'X-Signing-Token': portal_token(job),
        'X-XSign-Job-ID': str(job['id']),
        'X-XSign-Bundle-ID': main_spec.new_id,
        'X-XSign-Version': str(info.get('CFBundleShortVersionString') or '1.0')[:40],
        'X-XSign-Build': str(info.get('CFBundleVersion') or '1')[:40],
        'X-XSign-Display-Name': display_name[:80],
        'X-XSign-Min-IOS': str(info.get('MinimumOSVersion') or '15.0')[:20],
        'X-XSign-Profile-Expires': expiration[:60],
        'X-File-SHA256': digest.hexdigest(),
        'X-File-Name': urllib.parse.quote(filename, safe='._-'),
        'X-File-Size': str(size),
        'User-Agent': f'XSign-GitHub-Worker/{WORKER_VERSION}',
    }
    with ipa.open('rb') as stream:
        response = requests.put(
            callback_url,
            headers=headers,
            data=stream,
            timeout=(30, 900),
            allow_redirects=False,
        )
    if response.status_code < 200 or response.status_code >= 300:
        raise WorkerError(f'Portal signed IPA upload failed ({response.status_code}): {response.text[:500]}')


def report_portal_failure(job: dict[str, Any], message: str) -> None:
    callback_url = str(job.get('callbackUrl') or '').strip()
    if not callback_url:
        return
    try:
        failed_url = validated_portal_url(callback_url, 'callback') + '/failed'
        response = requests.post(
            failed_url,
            headers={
                'X-Signing-Token': portal_token(job),
                'User-Agent': f'XSign-GitHub-Worker/{WORKER_VERSION}',
            },
            json={'jobId': str(job['id']), 'error': message[:500]},
            timeout=(30, 120),
            allow_redirects=False,
        )
        if response.status_code < 200 or response.status_code >= 300:
            print(f'Could not report failure to portal: HTTP {response.status_code}')
    except Exception as exc:
        print(f'Could not report failure to portal: {exc}')


def upload_output(client: XSignClient, job_id: str, ipa: Path) -> int:
    count = 0
    with ipa.open('rb') as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            client.output_chunk(job_id, count, chunk)
            count += 1
    if count == 0:
        raise WorkerError('Signed IPA is empty.')
    return count


def prepare_profiles(
    apple: AppleClient,
    specs: list[BundleSpec],
    device_resource: str,
    cert_resource: str,
    work: Path,
    udid: str,
) -> None:
    for index, spec in enumerate(specs):
        spec.bundle_resource_id = apple.get_or_create_bundle_id(spec.new_id, spec.display_name)
        if spec.needs_push:
            apple.ensure_capability(spec.bundle_resource_id, 'PUSH_NOTIFICATIONS')
        profile_name = f"XSign-{hashlib.sha1(spec.new_id.encode()).hexdigest()[:10]}-{udid[-8:]}-{cert_resource[-6:]}-{pysecrets.token_hex(4).upper()}"
        profile_bytes, expiration = apple.get_or_create_profile(
            profile_name,
            spec.bundle_resource_id,
            device_resource,
            cert_resource,
        )
        profile_path = work / f'profile-{index}.mobileprovision'
        profile_path.write_bytes(profile_bytes)
        spec.profile_path = profile_path
        spec.expiration = expiration


def process_job(xs: XSignClient, apple: AppleClient, job: dict[str, Any]) -> None:
    job_id = str(job['id'])
    REDACTOR.register(str(job.get('udid') or ''))
    REDACTOR.register(job.get('sourceUrl'))
    REDACTOR.register(job.get('callbackUrl'))
    REDACTOR.register(job.get('signingToken'))
    with tempfile.TemporaryDirectory(prefix='xsign-') as td:
        work = Path(td)
        input_ipa = work / 'input.ipa'
        output_ipa = work / 'signed.ipa'
        p12 = work / 'distribution.p12'

        xs.status(job_id, 'registering_device', 'تنزيل IPA وفحص بنية التطبيق')
        download_input(xs, job, input_ipa)
        prefix = os.environ.get('APPLE_BUNDLE_PREFIX', DEFAULT_BUNDLE_PREFIX).strip() or DEFAULT_BUNDLE_PREFIX
        app, specs = inspect_and_remap(input_ipa, work, prefix)
        print('Bundle mapping:')
        for spec in specs:
            print(f'  {spec.original_id} -> {spec.new_id}')

        p12_password, reused_identity = bootstrap_signing_identity(xs, apple, p12, work)
        try:
            keychain, identity, serial = import_p12(p12, p12_password, work)
        except WorkerError as exc:
            if not reused_identity:
                raise
            print(f'Persisted signing identity is not macOS-compatible ({exc}); rewrapping it.')
            p12_password = rewrap_signing_identity(xs, p12, p12_password, work)
            keychain, identity, serial = import_p12(p12, p12_password, work)
        cert_id = apple.certificate_id_for_serial(serial)

        xs.status(job_id, 'registering_device', 'تسجيل جهاز iPhone لدى Apple Developer')
        device_id = apple.get_or_register_device(str(job['udid']), str(job.get('deviceName') or 'XSign iPhone'))

        xs.status(job_id, 'creating_profile', 'إنشاء App IDs وملفات Provisioning للتطبيق والإضافات')
        prepare_profiles(apple, specs, device_id, cert_id, work, str(job['udid']))

        xs.status(job_id, 'signing', 'توقيع الإضافات ثم التطبيق الرئيسي')
        for index, spec in enumerate([s for s in specs if s.is_extension]):
            assert spec.profile_path is not None
            shutil.copy2(spec.profile_path, spec.path / 'embedded.mobileprovision')
            entitlements, decoded_expiration = profile_entitlements(spec.profile_path, work / f'ext-{index}')
            if not spec.expiration:
                spec.expiration = decoded_expiration
            sign_bundle(spec, identity, keychain, entitlements)

        main_spec = next(s for s in specs if not s.is_extension)
        assert main_spec.profile_path is not None
        shutil.copy2(main_spec.profile_path, app / 'embedded.mobileprovision')
        main_entitlements, decoded_expiration = profile_entitlements(main_spec.profile_path, work / 'main')
        if not main_spec.expiration:
            main_spec.expiration = decoded_expiration
        sign_bundle(main_spec, identity, keychain, main_entitlements)

        xs.status(job_id, 'verifying', 'التحقق من التواقيع وبناء IPA النهائي')
        run(['codesign', '--verify', '--deep', '--strict', '--verbose=2', str(app)])
        repack(work / 'unpacked', output_ipa)

        filename = re.sub(r'(?i)\.ipa$', '', str(job['filename'])) + '-signed.ipa'
        if job.get('callbackUrl'):
            xs.status(job_id, 'uploading_result', 'رفع النسخة الموقعة إلى بوابة العميل')
            upload_portal_output(job, output_ipa, app, main_spec, filename)
            xs.portal_complete(job_id, filename, main_spec.expiration)
        else:
            xs.status(job_id, 'uploading_result', 'رفع النسخة الموقعة إلى XSign')
            chunk_count = upload_output(xs, job_id, output_ipa)
            xs.complete(job_id, chunk_count, filename, main_spec.expiration)
        print(f'[{job_id}] ready: {filename}')


def inspect_only(ipa_path: str, bundle_prefix: str) -> int:
    ipa = Path(ipa_path)
    with tempfile.TemporaryDirectory(prefix='xsign-inspect-') as td:
        _, specs = inspect_and_remap(ipa, Path(td), bundle_prefix)
        print(json.dumps({
            'ipa': ipa.name,
            'bundlePrefix': bundle_prefix,
            'bundles': [
                {
                    'kind': 'extension' if s.is_extension else 'app',
                    'name': s.display_name,
                    'originalBundleId': s.original_id,
                    'signedBundleId': s.new_id,
                    'needsPush': s.needs_push,
                }
                for s in specs
            ],
        }, ensure_ascii=False, indent=2))
    return 0


FALLBACK_REQUIRED_ENV_VARS: tuple[str, ...] = (
    'APPLE_ISSUER_ID',
    'APPLE_KEY_ID',
    'APPLE_PRIVATE_KEY',
    'APPLE_P12_BASE64',
    'APPLE_P12_PASSWORD',
    'SIGNING_API_BASE',
    'SIGNING_API_TOKEN',
)
FALLBACK_SECRET_LABELS: frozenset[str] = frozenset(FALLBACK_REQUIRED_ENV_VARS)


class MissingSecretsError(WorkerError):
    def __init__(self, missing: list[str]) -> None:
        self.missing = [name for name in missing if name in FALLBACK_SECRET_LABELS]
        super().__init__(
            'Direct Apple signing fallback is not configured; missing secrets: '
            + ', '.join(self.missing)
        )


def check_fallback_secrets() -> list[str]:
    return [name for name in FALLBACK_REQUIRED_ENV_VARS if not os.environ.get(name, '').strip()]


def missing_secret_message(name: str) -> str:
    # Only fixed, whitelisted environment-variable names are ever reported.
    label = name if name in FALLBACK_SECRET_LABELS else 'UNKNOWN'
    return 'Direct Apple signing fallback unavailable; missing: ' + label


def run_fallback_direct_signing() -> int:
    missing = check_fallback_secrets()
    if missing:
        jlog(
            'fallback_unavailable',
            missing_count=len(missing),
            message='Fallback signing disabled; jobs stay queued for the XSign worker.',
        )
        for name in missing:
            if name in FALLBACK_SECRET_LABELS:
                jlog('fallback_secret_missing', secret_name=name)
        return 2
    for name in ('APPLE_PRIVATE_KEY', 'APPLE_P12_BASE64', 'APPLE_P12_PASSWORD', 'SIGNING_API_TOKEN'):
        REDACTOR.register(os.environ.get(name))
    jlog(
        'fallback_not_implemented',
        message='Direct Apple signing secrets detected, but the fallback path requires '
                'SIGNING_API_BASE job orchestration that is not implemented in this worker. '
                'Jobs stay queued; do not mark them as signed.',
    )
    return 3


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument('--max-jobs', type=int, default=5)
    parser.add_argument('--inspect-ipa')
    parser.add_argument('--bundle-prefix', default=DEFAULT_BUNDLE_PREFIX)
    parser.add_argument('--health-check', action='store_true', help='Probe XSign reachability without claiming a job and exit.')
    parser.add_argument('--dry-run', action='store_true', help='Exercise one claim cycle without marking any job completed.')
    parser.add_argument('--fallback', action='store_true', help='Run the direct Apple signing fallback path.')
    parser.add_argument('--max-retry-seconds', type=float, default=RETRY_MAX_DURATION_SECONDS, help='Maximum backoff budget per XSign API call.')
    return parser


def health_check(args: argparse.Namespace) -> int:
    xs = XSignClient(max_retry_seconds=min(args.max_retry_seconds, HEALTH_RETRY_MAX_DURATION_SECONDS))
    try:
        xs.health_check()
    except RetryableAPIError as exc:
        jlog('health_check', status='unavailable', error=str(exc)[:200])
        return 1
    except WorkerError as exc:
        jlog('health_check', status='failed', error=str(exc)[:200])
        return 1
    jlog('health_check', status='ok', base_url=xs.base)
    return 0


def github_summary_lines(summary: dict[str, Any]) -> list[str]:
    lines = [
        '## XSign worker run',
        '',
        f"- Runner: `{summary.get('runner', 'github-macos')}`",
        f"- XSign health: `{summary.get('health', 'unknown')}`",
        f"- Jobs claimed: **{summary.get('claimed', 0)}**",
        f"- Jobs completed: **{summary.get('completed', 0)}**",
        f"- Jobs deferred: **{summary.get('deferred', 0)}**",
        f"- Jobs failed: **{summary.get('failed', 0)}**",
        f"- XSign API requests: {summary.get('requests', 0)}",
    ]
    missing = summary.get('fallback_missing')
    if missing:
        for name in missing:
            if name in FALLBACK_SECRET_LABELS:
                lines.append('- Fallback secret missing: `' + name + '`')
    return lines


def write_github_summary(summary: dict[str, Any]) -> None:
    path = os.environ.get('GITHUB_STEP_SUMMARY', '').strip()
    if not path:
        return
    rendered = github_summary_lines(summary)
    try:
        with open(path, 'a', encoding='utf-8') as handle:
            for line in rendered:
                handle.write(line + '\n')
    except OSError as exc:
        jlog('summary_write_failed', error=str(exc))


def run_worker(args: argparse.Namespace) -> int:
    xs = XSignClient(max_retry_seconds=args.max_retry_seconds)
    apple = AppleClient(xs)
    summary: dict[str, Any] = {
        'runner': os.environ.get('RUNNER_NAME', 'github-macos'),
        'health': 'unknown',
        'claimed': 0,
        'completed': 0,
        'deferred': 0,
        'failed': 0,
        'requests': 0,
    }
    exit_code = 0
    try:
        jlog('worker_start', base_url=xs.base, version=WORKER_VERSION)
        xs.heartbeat()
        xs.apple('ping')
        summary['health'] = 'ok'
        jlog('worker_ready', message='Heartbeat and Apple credentials verified; polling queue.')
        budget = max(1, min(args.max_jobs, 10))
        processed = 0
        while processed < budget:
            job = xs.claim()
            if not job:
                jlog('queue_empty', message='No queued XSign jobs.')
                break
            job_id = str(job.get('id') or '')
            if not job_id:
                summary['failed'] += 1
                jlog('job_invalid', message='Claimed job has no id; skipping.')
                break
            summary['claimed'] += 1
            jlog('job_claimed', job_id=job_id)
            try:
                process_job(xs, apple, job)
            except RetryableAPIError as exc:
                summary['deferred'] += 1
                summary['claimed'] -= 1
                jlog('job_deferred', job_id=job_id, error=str(exc)[:200])
                break
            except Exception as exc:
                summary['failed'] += 1
                message = REDACTOR.scrub(str(exc) or exc.__class__.__name__)
                jlog('job_failed', job_id=job_id, error=message[:300])
                report_portal_failure(job, message)
                xs.fail(job_id, message)
            else:
                summary['completed'] += 1
                jlog('job_completed', job_id=job_id)
            processed += 1
            try:
                xs.heartbeat()
            except RetryableAPIError as exc:
                jlog('heartbeat_degraded', error=str(exc)[:200])
                if processed < budget:
                    summary['deferred'] += 1
                break
    except DeferJobs as exc:
        summary['deferred'] += 1
        jlog('worker_deferred', message=str(exc)[:300])
    except RetryableAPIError as exc:
        summary['deferred'] += 1
        jlog('worker_deferred', error=str(exc)[:300])
    except WorkerError as exc:
        exit_code = 1
        jlog('worker_error', error=str(exc)[:300])
    finally:
        summary['requests'] = xs.request_count
        missing = check_fallback_secrets()
        if missing:
            summary['fallback_missing'] = missing
        write_github_summary(summary)
        jlog(
            'worker_summary',
            claimed=summary['claimed'],
            completed=summary['completed'],
            deferred=summary['deferred'],
            failed=summary['failed'],
            health=summary['health'],
            requests=summary['requests'],
        )
    return exit_code


def main() -> int:
    args = build_parser().parse_args()

    if args.inspect_ipa:
        return inspect_only(args.inspect_ipa, args.bundle_prefix)
    if args.health_check:
        return health_check(args)
    if args.fallback:
        return run_fallback_direct_signing()
    if args.dry_run:
        return run_dry_run(args)
    return run_worker(args)


def run_dry_run(args: argparse.Namespace) -> int:
    xs = XSignClient(max_retry_seconds=min(args.max_retry_seconds, HEALTH_RETRY_MAX_DURATION_SECONDS))
    xs.heartbeat()
    xs.apple('ping')
    job = xs.claim()
    if not job:
        jlog('dry_run', result='queue_empty', message='Heartbeat ok; no job available to dry-run.')
        return 0
    job_id = str(job.get('id') or '')
    jlog(
        'dry_run',
        result='would_process',
        job_id=job_id,
        udid_present=bool(str(job.get('udid') or '').strip()),
        callback=bool(str(job.get('callbackUrl') or '').strip()),
        filename=str(job.get('filename') or ''),
    )
    jlog('dry_run', result='deferred', job_id=job_id, message='Dry-run complete; job left in place.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
