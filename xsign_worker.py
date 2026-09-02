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
import urllib.parse
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import requests

CHUNK_SIZE = 384 * 1024
DEFAULT_BUNDLE_PREFIX = 'com.moha700m.xsign'
WORKER_VERSION = '3.2.12'


class WorkerError(RuntimeError):
    pass


def required_env(name: str) -> str:
    value = os.environ.get(name, '').strip()
    if not value:
        raise WorkerError(f'Missing required environment value: {name}')
    return value


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
    return token


class XSignClient:
    def __init__(self) -> None:
        self.base = os.environ.get('XSIGN_BASE_URL', 'https://api-v2.appdeploy.ai/app/xsign-0xcfp9').rstrip('/')
        self.s = requests.Session()
        self.s.headers.update({
            'Authorization': f'Bearer {github_oidc_token()}',
            'User-Agent': f'XSign-GitHub-Worker/{WORKER_VERSION}',
        })

    def _decode(self, response: requests.Response) -> dict[str, Any]:
        try:
            data = response.json()
        except Exception:
            data = {'error': response.text[:1000]}
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
        r = self.s.request(method, f'{self.base}{path}', json=json_body, timeout=120)
        data = self._decode(r)
        if not r.ok and r.status_code not in allow_statuses:
            raise WorkerError(f'XSign {method} {path} -> {r.status_code}: {data}')
        return r.status_code, data

    def heartbeat(self) -> None:
        self.request('POST', '/api/worker/heartbeat', json_body={'workerId': 'github-macos', 'version': WORKER_VERSION})

    def claim(self) -> dict[str, Any] | None:
        _, data = self.request('POST', '/api/worker/claim', json_body={})
        return data.get('job')

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
        status, data = self.request('GET', '/api/worker/signing-identity', allow_statuses=(503, 404))
        if status in (503, 404):
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

    def create_distribution_certificate(self, csr_content: str) -> dict[str, Any]:
        return self.xs.apple('certificate.create', csrContent=csr_content)

    def certificate_id_for_serial(self, serial: str) -> str:
        return str(self.xs.apple('certificate.lookup', serial=serial)['id'])

    def get_or_register_device(self, udid: str, name: str) -> str:
        return str(self.xs.apple('device.ensure', udid=udid, name=name)['id'])

    def get_or_create_bundle_id(self, bundle_id: str, display_name: str) -> str:
        return str(self.xs.apple('bundle.ensure', identifier=bundle_id, name=display_name)['id'])

    def ensure_capability(self, bundle_resource_id: str, capability_type: str) -> None:
        self.xs.apple('capability.ensure', bundleId=bundle_resource_id, capabilityType=capability_type)

    def get_or_create_profile(
        self,
        name: str,
        bundle_resource: str,
        device_resource: str,
        certificate_resource: str,
    ) -> tuple[bytes, str | None]:
        data = self.xs.apple(
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
    print('Creating a macOS-compatible XSign signing identity through Apple API.')
    private_key = work / 'distribution-private.pem'
    csr = work / 'distribution.csr'
    cert_der = work / 'distribution.cer'
    cert_pem = work / 'distribution.pem'
    password = pysecrets.token_hex(36)

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
    print('Persisted new XSign signing identity in encrypted AppDeploy storage.')
    return password


def bootstrap_signing_identity(
    xs: XSignClient,
    apple: AppleClient,
    p12: Path,
    work: Path,
) -> tuple[str, bool]:
    existing = xs.get_signing_identity()
    if existing:
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
    print('Rewrapped the persisted signing identity for macOS keychain compatibility.')
    return new_password


def import_p12(p12: Path, password: str, work: Path) -> tuple[Path, str, str]:
    keychain = work / f'{work.name}.keychain-db'
    keychain_password = pysecrets.token_urlsafe(32)
    run(['security', 'create-keychain', '-p', keychain_password, str(keychain)])
    run(['security', 'set-keychain-settings', '-lut', '21600', str(keychain)])
    run(['security', 'unlock-keychain', '-p', keychain_password, str(keychain)])
    # codesign only searches keychains in the user's search list. Register this
    # temporary keychain as both the active search and default keychain.
    run(['security', 'list-keychains', '-d', 'user', '-s', str(keychain)])
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


def remove_existing_signature(target: Path) -> None:
    # Existing signatures can contain requirements/entitlements from the original
    # developer team. Remove them before applying the new profile and identity.
    resolved = target.resolve()
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


PORTAL_HOST = 'xmod-store-mohammed.moha702m.chatgpt.site'
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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--max-jobs', type=int, default=5)
    parser.add_argument('--inspect-ipa')
    parser.add_argument('--bundle-prefix', default=DEFAULT_BUNDLE_PREFIX)
    args = parser.parse_args()

    if args.inspect_ipa:
        return inspect_only(args.inspect_ipa, args.bundle_prefix)

    xs = XSignClient()
    apple = AppleClient(xs)
    xs.heartbeat()
    xs.apple('ping')
    print('Apple API credentials verified.')
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
            report_portal_failure(job, message)
            xs.fail(str(job['id']), message)
        processed += 1
        xs.heartbeat()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
