#!/usr/bin/env python3
from __future__ import annotations

import plistlib
from pathlib import Path
from typing import Any

import xsign_worker as worker

_SIGNED_METADATA: dict[str, str] = {}
_original_inspect_and_remap = worker.inspect_and_remap


def inspect_and_remap(ipa: Path, work: Path, bundle_prefix: str):
    app, specs = _original_inspect_and_remap(ipa, work, bundle_prefix)
    main_spec = next(spec for spec in specs if not spec.is_extension)
    info: dict[str, Any] = {}
    try:
        with (app / 'Info.plist').open('rb') as handle:
            loaded = plistlib.load(handle)
            if isinstance(loaded, dict):
                info = loaded
    except Exception:
        info = {}

    _SIGNED_METADATA.clear()
    _SIGNED_METADATA.update({
        'bundleId': main_spec.new_id,
        'bundleVersion': str(
            info.get('CFBundleVersion')
            or info.get('CFBundleShortVersionString')
            or '1'
        ),
        'appTitle': str(
            info.get('CFBundleDisplayName')
            or info.get('CFBundleName')
            or main_spec.display_name
            or 'XSign App'
        )[:120],
    })
    return app, specs


def complete_with_install_metadata(
    self: worker.XSignClient,
    job_id: str,
    chunk_count: int,
    filename: str,
    expiration: str | None,
) -> None:
    payload: dict[str, Any] = {
        'chunkCount': chunk_count,
        'filename': filename,
        **_SIGNED_METADATA,
    }
    if expiration:
        payload['expirationDate'] = expiration
    self.request('POST', f'/api/worker/jobs/{job_id}/complete', json_body=payload)


worker.inspect_and_remap = inspect_and_remap
worker.XSignClient.complete = complete_with_install_metadata


if __name__ == '__main__':
    raise SystemExit(worker.main())
