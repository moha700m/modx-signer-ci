#!/usr/bin/env python3
import json
import os
import plistlib
import secrets
import shutil
import subprocess
import tempfile
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

JOB_ID = os.environ['JOB_ID']
API_BASE = os.environ['API_BASE'].rstrip('/')
WORKER_TOKEN = os.environ['WORKER_TOKEN']


def run(*args: str, cwd: str | None = None, capture: bool = True) -> subprocess.CompletedProcess:
    result = subprocess.run(args, cwd=cwd, text=True, capture_output=capture)
    if result.returncode != 0:
        raise RuntimeError({'cmd': list(args), 'stdout': result.stdout, 'stderr': result.stderr})
    return result


def api_url(path: str) -> str:
    return f"{API_BASE}{path}{'&' if '?' in path else '?'}token={urllib.parse.quote(WORKER_TOKEN)}"


def api_get(path: str) -> dict:
    req = urllib.request.Request(api_url(path), headers={'Accept': 'application/json'})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read().decode('utf-8'))


def api_post(path: str, payload: dict) -> dict:
    body = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(api_url(path), data=body, method='POST', headers={'Content-Type': 'application/json', 'Accept': 'application/json'})
    with urllib.request.urlopen(req, timeout=60) as resp:
        raw = resp.read()
        return json.loads(raw.decode('utf-8')) if raw else {}


def download(url: str, dest: Path) -> None:
    req = urllib.request.Request(url, headers={'User-Agent': 'MODX-Signer/1.0'})
    with urllib.request.urlopen(req, timeout=300) as resp, dest.open('wb') as out:
        shutil.copyfileobj(resp, out, length=1024 * 1024)


def callback(status: str, message: str) -> None:
    try:
        api_post(f'/api/worker/jobs/{JOB_ID}/progress', {'status': status, 'message': message})
    except Exception:
        pass


def parse_profile(profile_path: Path) -> dict:
    xml = run('security', 'cms', '-D', '-i', str(profile_path)).stdout.encode('utf-8')
    return plistlib.loads(xml)


def import_identity(p12_path: Path, password: str, keychain: Path) -> str:
    keychain_password = secrets.token_urlsafe(24)
    run('security', 'create-keychain', '-p', keychain_password, str(keychain))
    run('security', 'set-keychain-settings', '-lut', '21600', str(keychain))
    run('security', 'unlock-keychain', '-p', keychain_password, str(keychain))
    run('security', 'import', str(p12_path), '-k', str(keychain), '-P', password, '-T', '/usr/bin/codesign')
    run('security', 'set-key-partition-list', '-S', 'apple-tool:,apple:,codesign:', '-s', '-k', keychain_password, str(keychain))
    output = run('security', 'find-identity', '-v', '-p', 'codesigning', str(keychain)).stdout
    for line in output.splitlines():
        parts = line.strip().split()
        if len(parts) >= 2 and len(parts[1]) == 40:
            return parts[1]
    raise RuntimeError('No valid code-signing identity was found in the supplied P12')


def sign_bundle(app_dir: Path, identity: str, entitlements: Path) -> None:
    unsupported = list(app_dir.rglob('*.appex'))
    if unsupported:
        raise RuntimeError('This signer currently requires an IPA without app extensions (.appex).')

    targets: list[Path] = []
    targets.extend(app_dir.rglob('*.framework'))
    targets.extend(app_dir.rglob('*.dylib'))
    targets.extend(app_dir.rglob('*.bundle'))
    targets = sorted(set(targets), key=lambda p: len(p.parts), reverse=True)

    for target in targets:
        if target.is_dir() and target.suffix == '.bundle':
            continue
        run('codesign', '--force', '--sign', identity, '--timestamp=none', '--preserve-metadata=identifier,flags', str(target))

    run('codesign', '--force', '--sign', identity, '--timestamp=none', '--entitlements', str(entitlements), str(app_dir))
    run('codesign', '--verify', '--deep', '--strict', '--verbose=2', str(app_dir))


def upload_file(url: str, file_path: Path, headers: dict[str, str]) -> None:
    args = ['curl', '--fail', '--silent', '--show-error', '--request', 'PUT', '--upload-file', str(file_path)]
    for key, value in headers.items():
        args.extend(['-H', f'{key}: {value}'])
    args.append(url)
    run(*args, capture=False)


def main() -> None:
    callback('running', 'جاري تجهيز ملفات التوقيع')
    payload = api_get(f'/api/worker/jobs/{JOB_ID}/payload')

    with tempfile.TemporaryDirectory(prefix='modx-signer-') as td:
        root = Path(td)
        ipa_path = root / 'input.ipa'
        p12_path = root / 'certificate.p12'
        profile_path = root / 'profile.mobileprovision'
        extract_dir = root / 'extract'
        output_ipa = root / 'signed.ipa'
        keychain = root / 'modx.keychain-db'

        callback('running', 'جاري تنزيل الملفات')
        download(payload['ipaUrl'], ipa_path)
        download(payload['p12Url'], p12_path)
        download(payload['provisionUrl'], profile_path)

        callback('running', 'جاري فحص ملف IPA')
        with zipfile.ZipFile(ipa_path, 'r') as archive:
            archive.testzip()
            archive.extractall(extract_dir)

        apps = list((extract_dir / 'Payload').glob('*.app'))
        if len(apps) != 1:
            raise RuntimeError('IPA must contain exactly one Payload/*.app bundle')
        app_dir = apps[0]
        info_path = app_dir / 'Info.plist'
        with info_path.open('rb') as f:
            info = plistlib.load(f)

        profile = parse_profile(profile_path)
        entitlements_dict = profile.get('Entitlements') or {}
        application_identifier = str(entitlements_dict.get('application-identifier', ''))
        profile_bundle_id = application_identifier.split('.', 1)[1] if '.' in application_identifier else ''
        app_bundle_id = str(info.get('CFBundleIdentifier', ''))
        if not profile_bundle_id:
            raise RuntimeError('Provisioning profile does not contain an application-identifier entitlement')
        if profile_bundle_id != app_bundle_id and not profile_bundle_id.endswith('*'):
            raise RuntimeError(f'Provisioning profile bundle ID {profile_bundle_id} does not match IPA bundle ID {app_bundle_id}')
        if profile_bundle_id.endswith('*') and not app_bundle_id.startswith(profile_bundle_id[:-1]):
            raise RuntimeError(f'Wildcard provisioning profile {profile_bundle_id} does not match IPA bundle ID {app_bundle_id}')

        shutil.copy2(profile_path, app_dir / 'embedded.mobileprovision')
        entitlements_path = root / 'entitlements.plist'
        with entitlements_path.open('wb') as f:
            plistlib.dump(entitlements_dict, f, fmt=plistlib.FMT_XML)

        callback('running', 'جاري استيراد شهادة التوقيع')
        identity = import_identity(p12_path, payload['p12Password'], keychain)

        callback('running', 'جاري توقيع التطبيق')
        sign_bundle(app_dir, identity, entitlements_path)

        callback('running', 'جاري إنشاء IPA النهائي')
        with zipfile.ZipFile(output_ipa, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
            for item in extract_dir.rglob('*'):
                if item.is_file() or item.is_symlink():
                    archive.write(item, item.relative_to(extract_dir))
        with zipfile.ZipFile(output_ipa, 'r') as archive:
            bad = archive.testzip()
            if bad:
                raise RuntimeError(f'Final IPA archive failed validation at {bad}')

        callback('running', 'جاري رفع النسخة الموقعة')
        upload_file(payload['signedUploadUrl'], output_ipa, payload.get('signedUploadHeaders') or {})

        result = {
            'status': 'completed',
            'bundleId': app_bundle_id,
            'appName': str(info.get('CFBundleDisplayName') or info.get('CFBundleName') or app_dir.stem),
            'version': str(info.get('CFBundleShortVersionString') or ''),
            'build': str(info.get('CFBundleVersion') or ''),
            'signedSize': output_ipa.stat().st_size,
        }
        api_post(f'/api/worker/jobs/{JOB_ID}/complete', result)
        print('Signing job completed successfully')


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        message = str(exc)
        callback('failed', message[:1000])
        try:
            api_post(f'/api/worker/jobs/{JOB_ID}/complete', {'status': 'failed', 'error': message[:2000]})
        except Exception:
            pass
        raise
