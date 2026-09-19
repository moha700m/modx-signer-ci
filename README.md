# MOD X Signer CI

Private macOS signing builders for the MOD X / XSign signing services. This
repository contains two independent pipelines:

| Pipeline | Workflow | Purpose |
| --- | --- | --- |
| XSign queue worker | `.github/workflows/xsign-worker.yml` + `xsign_worker.py` | Polls the XSign signing service every 5 minutes and signs queued customer orders on a macOS runner. |
| Direct job runner | `.github/workflows/sign.yml` + `worker.py` | Signs one job when dispatched manually with a job id, API base, and one-time token (SignTools-style integration). |

This repository does **not** store certificates, provisioning profiles, P12
passwords, Apple credentials, private keys, device UDIDs, or signed customer
apps.

## Architecture

```text
Customer website (XMOD store)
        |  order created
        v
XSign API (AppDeploy backend, XSIGN_BASE_URL)
        |  POST /api/worker/claim  (queue)
        v
GitHub Actions macOS runner (macos-15)
  .github/workflows/xsign-worker.yml   (schedule: */5 min + manual dispatch)
      |  1. health check:  python3 xsign_worker.py --health-check
      |  2. warm loop:     python3 xsign_worker.py --max-jobs 10
        |      heartbeat -> claim -> download IPA -> Apple device/profile
        |      registration -> codesign -> repack -> upload -> complete
        v
Signed IPA uploaded to XSign / customer portal
        |
        v
Customer website shows accurate status (queued / signing / ready)
```

Supporting pieces:

- **Apple operations** (certificates, devices, bundle IDs, profiles) are proxied
  through `POST /api/worker/apple` on the XSign backend; no Apple credentials
  live in this repository.
- **Portal uploads** go only to the validated portal host
  (`XSIGN_PORTAL_HOST` variable, default `xmod-store-mohammed.moha702m.chatgpt.site`)
  over HTTPS with a per-job signing token.
- **Concurrency**: the workflow uses a single `xsign-signing-worker`
  concurrency group with `cancel-in-progress: false`, so two workers can never
  run at the same time and cannot claim the same job from this repository.

## What caused the HTTP 402 failure

The worker's heartbeat request

```text
POST {XSIGN_BASE_URL}/api/worker/heartbeat
```

was answered with `HTTP 402` and the body code `APP_TEMPORARILY_UNAVAILABLE`.
In this API, 402 is **not** a payment rejection of a customer order — it is the
backend's signal that the signing engine deployment is temporarily unavailable
(e.g. the AppDeploy deployment was marked "ready" before the worker API routes
were actually serving, or the route/URL changed).

The old worker treated 402 like any other error: it raised immediately from
`heartbeat()`, crashed, and the keep-warm loop restarted it every 10 seconds —
a hot failure loop. Because the heartbeat failed, `claim` was never reached, so
no signing job was picked up and customer orders stayed `pending` forever.

The fix in this repository:

1. `XSIGN_BASE_URL` is now read from the GitHub **variable** `XSIGN_BASE_URL`
   (repository *Settings → Secrets and variables → Actions → Variables*), so a
   backend URL/route change no longer requires a code commit. If the variable
   is unset, the worker falls back to the previously hardcoded default and logs
   a `config_default_base_url` event.
2. All XSign API calls retry `402, 408, 429, 500, 502, 503, 504` and network
   errors with exponential backoff (base 2s, max 60s, bounded by a per-call
   retry budget, default 180s; configurable with `--max-retry-seconds`).
3. When the outage outlives the retry budget, the worker raises a deferrable
   error, exits **0**, and reports the run as *deferred* — jobs stay queued and
   the next scheduled run (5 minutes later) tries again.
4. A safe health check (`--health-check`) probes heartbeat + Apple credentials
   **without claiming a job**, and the workflow gates the signing loop on it.
5. Jobs are only marked completed after the signed IPA is uploaded and the
   backend confirms completion; jobs are only marked failed for real signing
   errors — never for infrastructure outages.

Note: "AppDeploy deployment ready" only means the deployment finished; it does
not prove the worker API is healthy. Always run the health check (below) after
a backend deploy.

## Required GitHub configuration

### Variables (*Settings → Secrets and variables → Actions → Variables*)

| Variable | Required | Description |
| --- | --- | --- |
| `XSIGN_BASE_URL` | recommended | XSign worker API base, e.g. `https://api-v2.appdeploy.ai/app/xsign-0xcfp9`. Update here when the deployment URL changes. |
| `APPLE_BUNDLE_PREFIX` | optional | Reverse-DNS bundle prefix used for re-signing (default `com.moha700m.xsign`). |
| `XSIGN_PORTAL_HOST` | optional | Override the customer portal host that receives signed IPAs. |

### Secrets — XSign worker

The XSign worker authenticates with **GitHub OIDC** (`id-token: write`,
audience `xsign-worker`); no static token secret is needed. If the backend
rejects the token with 401/403, verify the configured OIDC audience matches
`xsign-worker` on the AppDeploy side.

### Secrets — optional direct Apple fallback

The fallback path only activates when **all** of the following exist. If any is
missing the worker prints exactly which ones and keeps customer jobs queued —
it never invents values and never fakes a successful signing.

| Secret | Description |
| --- | --- |
| `APPLE_ISSUER_ID` | App Store Connect API issuer id. |
| `APPLE_KEY_ID` | App Store Connect API key id. |
| `APPLE_PRIVATE_KEY` | App Store Connect API private key (PEM). |
| `APPLE_P12_BASE64` | Base64-encoded distribution signing identity. |
| `APPLE_P12_PASSWORD` | Password for the P12. |
| `SIGNING_API_BASE` | Base URL of the direct signing job API. |
| `SIGNING_API_TOKEN` | Authentication token for the direct signing job API. |

Do not commit any of these values to this repository.

## Running the health check

Locally or in CI, without claiming any job:

```bash
python3 -m pip install -r requirements-xsign.txt
XSIGN_BASE_URL="https://api-v2.appdeploy.ai/app/xsign-0xcfp9" \
  python3 xsign_worker.py --health-check
```

Exit code `0` = API reachable and Apple credentials valid; `1` = degraded
(structured `health_check` log line explains why). The GitHub workflow runs
this automatically before the polling loop and skips signing when it fails.

Other safe modes:

```bash
python3 xsign_worker.py --dry-run      # claim nothing permanently; report one job
python3 xsign_worker.py --fallback     # report fallback secret readiness
python3 xsign_worker.py --inspect-ipa path/to/app.ipa   # bundle-id mapping only
```

## Requeueing a deferred job safely

Deferred jobs are never removed from the XSign queue and never marked failed —
they simply stay `pending`. To requeue:

1. Fix the underlying condition (e.g. update `XSIGN_BASE_URL`, or wait for the
   AppDeploy worker API to recover).
2. Run the health check above until it exits `0`.
3. Either wait for the next scheduled run (every 5 minutes) or trigger
   **Actions → XSign macOS Signing Worker → Run workflow** manually.
4. Watch the run summary: *Jobs deferred* should drop and *Jobs completed*
   should increase.

Do **not** re-create the order on the website; the existing queued job is
claimed automatically once the worker is healthy.

## Inspecting logs without exposing credentials

- Worker logs are structured JSON lines (`jlog`); look at the `event` field:
  `http_retry`, `http_retry_exhausted`, `job_claimed`, `job_completed`,
  `job_deferred`, `job_failed`, `worker_summary`, `health_check`.
- Every run ends with a `worker_summary` event and a GitHub step summary with
  runner status, XSign health, jobs claimed / completed / deferred / failed,
  and the number of API requests.
- The worker redacts OIDC tokens, Apple credentials, UDIDs, provisioning
  profiles, IPA URLs, and private keys before printing: registered secret
  values are replaced with `***`, and JWTs, 40-char hex (UDIDs/certificate
  hashes), 64-char hex (signing tokens), and UUID job ids are masked
  automatically. Never add `print()` of raw payloads; use `jlog`.
- To share logs, download the GitHub Actions log archive — no extra scrubbing
  is needed as long as all output goes through `jlog`/the redactor.

## Direct job runner (`sign.yml` + `worker.py`)

`worker.py` signs a single IPA when a job id, API base, and one-time worker
token are supplied. It is kept as a tested manual fallback:

- **When to use**: integrating with a SignTools-style backend that dispatches
  one job at a time.
- **Inputs**: `job_id`, `api_base`, `worker_token` (all required, via
  *Run workflow*).
- **Limitations**: it cannot poll the XSign queue, requires an IPA without app
  extensions (`.appex`), and downloads the P12/profile per job — so it cannot
  process current XMOD portal orders. XMOD orders are served by
  `xsign-worker.yml` only.

## Upstream

The original SignTools-based flow used the official `SignTools/SignTools-CI`
project pinned to commit `8790863e64148768be9e8320c361411580d52554` to prevent
upstream changes from silently altering the signing code.

## Tests

```bash
python3 -m pip install -r requirements-xsign.txt pyyaml
python3 -m unittest discover -s tests -v
```

The suite covers HTTP 402 retry/backoff behavior, proof that a failed heartbeat
never claims a job, secret redaction, dry-run of successful and deferred jobs,
fallback secret reporting, YAML validation of all workflows, and Python syntax
checks. All network access is stubbed; tests run on any platform.

## Security

- Repository visibility must remain **Private**.
- Signing certificates, `.mobileprovision` files, and keys belong in the XSign /
  SignTools secret stores, not this repository.
- Rotate any credential that ever appears in a log.
- Only sign software you are authorized to distribute. See `SECURITY.md`.
