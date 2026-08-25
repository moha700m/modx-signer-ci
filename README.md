# MOD X Signer CI

Private macOS signing builder for the MOD X signing service.

## Architecture

`MOD X web/service` → `GitHub Actions macOS builder` → `SignTools CI` → signed IPA returned to the service.

This repository does **not** store certificates, provisioning profiles, P12 passwords, Apple credentials, or signed customer apps.

## Upstream

The workflow uses the official `SignTools/SignTools-CI` project pinned to commit:

`8790863e64148768be9e8320c361411580d52554`

This prevents an upstream branch update from silently changing the signing code used by the builder.

## Required GitHub Actions secrets

The SignTools service will provide these values when the service layer is configured:

- `SECRET_URL` — private SignTools service/job endpoint.
- `SECRET_KEY` — shared authentication key used between SignTools and the builder.

Do not commit either value to this repository.

## SignTools service configuration

Use this builder configuration in `signer-cfg.yml`:

```yaml
builder:
  github:
    enable: true
    repo_name: modx-signer-ci
    org_name: moha700m
    workflow_file_name: sign.yml
    token: YOUR_GITHUB_PAT
    ref: main
```

The GitHub PAT belongs in the SignTools service secret store, never in Git.

## Security

- Repository visibility must remain **Private**.
- Signing certificates and `.mobileprovision` files belong in the SignTools service/profile storage, not this repository.
- Rotate `SECRET_KEY` and the GitHub PAT if either is exposed.
- Only sign software you are authorized to distribute.
