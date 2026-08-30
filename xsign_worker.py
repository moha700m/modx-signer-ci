#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import plistlib
import re
import secrets as pysecrets
import shutil
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import jwt
import requests

CHUNK_SIZE = 384 * 1024
APPLE_API = 'https://api.appstoreconnect.apple.com'
DEFAULT_BUNDLE_PREFIX = 'com.moha700m.xsign'


class WorkerError(RuntimeError):
    pass


def required_env(name: str) -> str:
    value = os.environ.get(name, '').strip()
    if not value:
        raise WorkerError(f'Missing required secret/environment value: {name}')
    return value


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
        raise WorkerError(f"{' '.join(args[:4])} failed: {detail[:1600]}")
    return (proc.stdout or '').strip()


def github_oidc_token() -> str:
    request_url = required_env('ACTIONS_ID_TOKEN_REQUEST_URL')
    request_token = required_env('ACTIONS_ID_TOKEN_REQUEST_TOKEN')
    separator = '&' if '?' in request_url else '?'
    url = f'{request_url}{separator}audience={urllib.parse.quote("xsign-worker")}'
    req = urllib.request.Request(url, headers={'Authorization': f'Bearer {request_token}', 'Accept': 'application/json'})
    with urllib.request.urlopen(req, timeout=30) as response:
        payload = json.loads(response.read().decode('utf-8'))
    token = str(payload.get('value', '')).strip()
    if not token:
        raise WorkerError('GitHub Actions did not return an OIDC token.')
    return token


class XSignClient:
    def __init__(self) -> None:
        self.base = os.environ.get('XSIGN_BASE_URL', 'https://xsign-0xcfp9.v2.appdeploy.ai').rstrip('/')
        self.s = requests.Session()
        self.s.headers.update({'Authorization': f'Bearer {github_oidc_token()}', 'User-Agent': 'XSign-GitHub-Worker/2.0'})

    def request(self, method: str, path: str, *, json_body: dict[str, Any] | None = None) -> dict[str, Any]:
        r = self.s.request(method, f'{self.base}{path}', json=json_body, timeout=90)
        try:
            data = r.json()
        except Exception:
            data = {'error': r.text[:1000]}
        if not r.ok:
            raise WorkerError(f'XSign {method} {path} -> {r.status_code}: {data}')
        return data

    def heartbeat(self) -> None:
        self.request('POST', '/api/worker/heartbeat', json_body={'workerId': 'github-macos', 'version': '2.0.0'})

    def claim(self) -> dict[str, Any] | None:
        return self.request('POST', '/api/worker/claim', json_body={}).get('job')

    def status(self, job_id: str, status: str, message: str) -> None:
        self.request('POST', f'/api/worker/jobs/{job_id}/status', json_body={'status': status, 'message': message})

    def input_chunk(self, job_id: str, index: int) -> bytes:
        data = self.request('GET', f'/api/worker/jobs/{job_id}/input/{index}')
        return base64.b64decode(data['content'], validate=True)

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

    def fail(self, job_id: str, message: str) -> None:
        try:
            self.request('POST', f'/api/worker/jobs/{job_id}/fail', json_body={'message': message[:500]})
        except Exception as exc:
            print(f'Could not report failure to XSign: {exc}')


class AppleClient:
    def __init__(self) -> None:
        self.issuer = required_env('APPLE_ISSUER_ID')
        self.key_id = required_env('APPLE_KEY_ID')
        try:
            self.private_key = base64.b64decode(required_env('APPLE_PRIVATE_KEY_P8_B64'), validate=True).decode('utf-8')
        except Exception as exc:
            raise WorkerError('APPLE_PRIVATE_KEY_P8_B64 is not valid base64-encoded P8 content.') from exc
        self.s = requests.Session()

    def token(self) -> str:
        now = int(time.time())
        return jwt.encode(
            {'iss': self.issuer, 'iat': now, 'exp': now + 900, 'aud': 'appstoreconnect-v1'},
            self.private_key,
            algorithm='ES256',
            headers={'kid': self.key_id, 'typ': 'JWT'},
        )

    def request(self, method: str, path: str, *, params: dict[str, str] | None = None, body: dict[str, Any] | None = None) -> dict[str, Any]:
        headers = {'Authorization': f'Bearer {self.token()}', 'Content-Type': 'application/json'}
        r = self.s.request(method, f'{APPLE_API}{path}', params=params, json=body, headers=headers, timeout=90)
        try:
            data = r.json()
        except Exception:
            data = {'raw': r.text[:1000]}
        if not r.ok:
            errors = data.get('errors') if isinstance(data, dict) else None
            raise WorkerError(f'Apple API {method} {path} -> {r.status_code}: {errors or data}')
        return data

    def get_or_register_device(self, udid: str, name: str) -> str:
        data = self.request('GET', '/v1/devices', params={'filter[udid]': udid, 'limit': '10'})
        devices = data.get('data', [])
        if devices:
            device = devices[0]
            attrs = device.get('attributes', {})
            if attrs.get('status') == 'DISABLED':
                raise WorkerError('This UDID exists in Apple Developer but is disabled.')
            return device['id']
        body = {'data': {'type': 'devices', 'attributes': {'name': name[:50] or 'XSign iPhone', 'platform': 'IOS', 'udid': udid}}}
        return self.request('POST', '/v1/devices', body=body)['data']['id']

    def get_or_create_bundle_id(self, bundle_id: str, display_name: str) -> str:
        data = self.request('GET', '/v1/bundleIds', params={'filter[identifier]': bundle_id, 'limit': '10'})
        items = data.get('data', [])
        if items:
            return items[0]['id']
        safe_name = re.sub(r'[^A-Za-z0-9 ._-]+', '-', display_name).strip() or 'XSign App'
        body = {
            'data': {
                'type': 'bundleIds',
                'attributes': {'identifier': bundle_id, 'name': f'XSign {safe_name}'[:100], 'platform': 'IOS'},
            }
        }
        return self.request('POST', '/v1/bundleIds', body=body)['data']['id']

    def ensure_capability(self, bundle_resource_id: str, capability_type: str) -> None:
        data = self.request('GET', f'/v1/bundleIds/{bundle_resource_id}/bundleIdCapabilities', params={'limit': '200'})
        for item in data.get('data', []):
            if item.get('attributes', {}).get('capabilityType') == capability_type:
                return
        body = {
            'data': {
                'type': 'bundleIdCapabilities',
                'attributes': {'capabilityType': capability_type},
                'relationships': {'bundleId': {'data': {'type': 'bundleIds', 'id': bundle_resource_id}}},
            }
        }
        self.request('POST', '/v1/bundleIdCapabilities', body=body)

    def certificate_id_for_serial(self, serial: str) -> str:
        candidates = [serial.upper().lstrip('0'), serial.upper()]
        for candidate in dict.fromkeys(candidates):
            data = self.request('GET', '/v1/certificates', params={'filter[serialNumber]': candidate, 'limit': '10'})
            items = [x for x in data.get('data', []) if x.get('attributes', {}).get('activated', True)]
            if items:
                return items[0]['id']
        raise WorkerError(f'Apple Distribution certificate serial {serial} was not found in this developer team.')

    def get_or_create_profile(self, name: str, bundle_resource: str, device_resource: str, certificate_resource: str) -> tuple[bytes, str | None]:
        data = self.request('GET', '/v1/profiles', params={'filter[name]': name, 'limit': '10'})
        for item in data.get('data', []):
            attrs = item.get('attributes', {})
            content = attrs.get('profileContent')
            if content and attrs.get('profileState') != 'INVALID':
                return base64.b64decode(content), attrs.get('expirationDate')
        body = {
            'data': {
                'type': 'profiles',
                'attributes': {'name': name[:100], 'profileType': 'IOS_APP_ADHOC'},
                'relationships': {
                    'bundleId': {'data': {'type': 'bundleIds', 'id': bundle_resource}},
                    'devices': {'data': [{'type': 'devices', 'id': device_resource}]},
                    'certificates': {'data': [{'type': 'certificates', 'id': certificate_resource}]},
                },
            }
        }
        data = self.request('POST', '/v1/profiles', body=body)['data']
        attrs = data['attributes']
        return base64.b64decode(attrs['profileContent']), attrs.get('expirationDate')


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
    if original_main.startswith(prefix + '.'):
        new_main = original_main
    else:
        base = slug(original_main.split('.')[-1] or app.stem, 'app')
        new_main = f'{prefix}.{base}'

    extension_dirs = sorted(app.glob('PlugIns/*.appex'))
    has_notification_service = False
    specs: list[BundleSpec] = []
    ext_infos: list[tuple[Path, Path, dict[str, Any], str, str]] = []
    for ext in extension_dirs:
        info_path, info = read_info(ext)
        original_id = str(info.get('CFBundleIdentifier', '')).strip()
        if not original_id:
            raise WorkerError(f'{ext.name} CFBundleIdentifier is missing.')
        ext_name = str(info.get('CFBundleDisplayName') or info.get('CFBundleName') or ext.stem).strip()
        if original_id.startswith(original_main + '.'):
            suffix = original_id[len(original_main) + 1:]
        else:
            suffix = ext.stem
        suffix = '.'.join(slug(part, 'ext') for part in suffix.split('.'))
        new_id = f'{new_main}.{suffix}'
        point = str((info.get('NSExtension') or {}).get('NSExtensionPointIdentifier', ''))
        if point == 'com.apple.usernotifications.service':
            has_notification_service = True
        ext_infos.append((ext, info_path, info, original_id, new_id))

    background_modes = main_info.get('UIBackgroundModes') or []
    main_needs_push = has_notification_service or 'remote-notification' in background_modes
    main_info['CFBundleIdentifier'] = new_main
    write_info(main_info_path, main_info)
    specs.append(BundleSpec(app, main_info_path, original_main, new_main, display_name, False, main_needs_push))

    mapping = {original_main: new_main}
    for ext, info_path, info, original_id, new_id in ext_infos:
        info['CFBundleIdentifier'] = new_id
        for key in ('WKCompanionAppBundleIdentifier',):
            if info.get(key) in mapping:
                info[key] = mapping[info[key]]
        write_info(info_path, info)
        mapping[original_id] = new_id
        ext_name = str(info.get('CFBundleDisplayName') or info.get('CFBundleName') or ext.stem).strip()
        specs.append(BundleSpec(ext, info_path, original_id, new_id, ext_name, True, False))

    return app, specs


def decode_secret_file(name: str, output: Path) -> None:
    try:
        output.write_bytes(base64.b64decode(required_env(name), validate=True))
    except Exception as exc:
        raise WorkerError(f'{name} is not valid base64.') from exc


def import_p12(p12: Path, password: str, work: Path) -> tuple[Path, str, str]:
    keychain = work / 'xsign.keychain-db'
    keychain_password = pysecrets.token_urlsafe(32)
    run(['security', 'create-keychain', '-p', keychain_password, str(keychain)])
    run(['security', 'set-keychain-settings', '-lut', '21600', str(keychain)])
    run(['security', 'unlock-keychain', '-p', keychain_password, str(keychain)])
    run(['security', 'import', str(p12), '-k', str(keychain), '-P', password, '-T', '/usr/bin/codesign', '-T', '/usr/bin/security'])
    run(['security', 'set-key-partition-list', '-S', 'apple-tool:,apple:,codesign:', '-s', '-k', keychain_password, str(keychain)])
    identities = run(['security', 'find-identity', '-v', '-p', 'codesigning', str(keychain)])
    match = re.search(r'\b([0-9A-F]{40})\b', identities)
    if not match:
        raise WorkerError('No code-signing identity was found in APPLE_DISTRIBUTION_P12_B64.')
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


def sign_code_objects(bundle: Path, identity: str, keychain: Path) -> None:
    targets: list[Path] = []
    for framework_dir in bundle.rglob('*.framework'):
        if any(part.endswith('.appex') for part in framework_dir.parts):
            continue
        targets.append(framework_dir)
    for dylib in bundle.rglob('*.dylib'):
        if any(part.endswith('.appex') for part in dylib.parts):
            continue
        targets.append(dylib)
    for target in sorted(set(targets), key=lambda p: len(p.parts), reverse=True):
        run([
            'codesign', '--force', '--sign', identity, '--keychain', str(keychain), '--timestamp=none',
            '--preserve-metadata=identifier,requirements,flags,runtime', str(target),
        ])


def sign_bundle(spec: BundleSpec, identity: str, keychain: Path, entitlements: Path) -> None:
    sign_code_objects(spec.path, identity, keychain)
    signature = spec.path / '_CodeSignature'
    if signature.exists():
        shutil.rmtree(signature)
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


def download_input(client: XSignClient, job: dict[str, Any], output: Path) -> None:
    with output.open('wb') as f:
        for index in range(int(job['chunkCount'])):
            f.write(client.input_chunk(job['id'], index))


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


def prepare_profiles(apple: AppleClient, specs: list[BundleSpec], device_resource: str, cert_resource: str, work: Path, job_id: str, udid: str) -> None:
    for index, spec in enumerate(specs):
        spec.bundle_resource_id = apple.get_or_create_bundle_id(spec.new_id, spec.display_name)
        if spec.needs_push:
            apple.ensure_capability(spec.bundle_resource_id, 'PUSH_NOTIFICATIONS')
        profile_name = f"XSign-{hashlib.sha1(spec.new_id.encode()).hexdigest()[:10]}-{udid[-8:]}-{cert_resource[-6:]}"
        profile_bytes, expiration = apple.get_or_create_profile(profile_name, spec.bundle_resource_id, device_resource, cert_resource)
        profile_path = work / f'profile-{index}.mobileprovision'
        profile_path.write_bytes(profile_bytes)
        spec.profile_path = profile_path
        spec.expiration = expiration


def process_job(xs: XSignClient, apple: AppleClient, job: dict[str, Any]) -> None:
    job_id = str(job['id'])
    with tempfile.TemporaryDirectory(prefix=f'xsign-{job_id[:8]}-') as td:
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

        decode_secret_file('APPLE_DISTRIBUTION_P12_B64', p12)
        p12_password = required_env('APPLE_DISTRIBUTION_P12_PASSWORD')
        keychain, identity, serial = import_p12(p12, p12_password, work)
        cert_id = apple.certificate_id_for_serial(serial)

        xs.status(job_id, 'registering_device', 'تسجيل جهاز iPhone لدى Apple Developer')
        device_id = apple.get_or_register_device(str(job['udid']), str(job.get('deviceName') or 'XSign iPhone'))

        xs.status(job_id, 'creating_profile', 'إنشاء App IDs وملفات Provisioning للتطبيق والإضافات')
        prepare_profiles(apple, specs, device_id, cert_id, work, job_id, str(job['udid']))

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

        xs.status(job_id, 'uploading_result', 'رفع النسخة الموقعة إلى XSign')
        chunk_count = upload_output(xs, job_id, output_ipa)
        filename = re.sub(r'(?i)\.ipa$', '', str(job['filename'])) + '-signed.ipa'
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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--max-jobs', type=int, default=5)
    parser.add_argument('--inspect-ipa')
    parser.add_argument('--bundle-prefix', default=DEFAULT_BUNDLE_PREFIX)
    args = parser.parse_args()

    if args.inspect_ipa:
        return inspect_only(args.inspect_ipa, args.bundle_prefix)

    xs = XSignClient()
    apple = AppleClient()
    xs.heartbeat()
    processed = 0
    while processed < max(1, min(args.max_jobs, 10)):
        job = xs.claim()
        if not job:
            print('No queued XSign jobs.')
            break
        try:
            process_job(xs, apple, job)
        except Exception as exc:
            message = str(exc) or exc.__class__.__name__
            print(f"[{job['id']}] FAILED: {message}")
            xs.fail(str(job['id']), message)
        processed += 1
        xs.heartbeat()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
