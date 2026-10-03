# AppDeploy backend patch: Profile Service enrollment (xsign-0xcfp9)

Reference implementation for the AppDeploy backend (lives outside this repo).
No secrets are included; Apple credentials stay in AppDeploy secrets.

## Why the old flow failed (root-cause analysis)

1. Download was started from an async-created `window.open('about:blank')` that
   was later redirected with `location.replace()`. iOS Safari only honours a
   configuration-profile download that is a top-level navigation caused directly
   by a user tap. The `await api.post(...)` between the tap and the navigation
   breaks the user-gesture chain, and the popup is blank/blocked. The fallback
   anchor was only shown after that failed attempt.
2. `Content-Disposition: attachment` is unnecessary. Apple's Profile Service
   documentation only requires `Content-Type: application/x-apple-aspen-config`;
   Safari decides on the MIME type and `attachment` can make it treat the
   response as a plain download instead of handing it to Settings.
3. The URL (`/api/enrollment/profile/:token`) has no `.mobileconfig` suffix;
   a suffix is a helpful hint, so use one.
4. `PayloadIdentifier` had a random suffix per generated profile. Profile Service
   profiles should use a stable identifier (a reverse-DNS id for the service) so
   a re-download replaces the pending profile rather than accumulating entries.
   `PayloadUUID` may stay unique per generation.
5. No `Challenge`: Apple lets the service put a `Challenge` in the Profile
   Service payload; the device echoes it in the signed response, which binds the
   response to the session.

Not a cause (verified against Apple docs): the structure
`PayloadType=Profile Service`, `PayloadContent{URL, DeviceAttributes}` is correct,
and `UDID/PRODUCT/VERSION/SERIAL` are valid DeviceAttributes.

## Backend code

```ts
const PROFILE_IDENTIFIER = 'com.xsign.store.enroll'; // stable

function enrollmentProfile(token: string, challenge: string) {
  const callback = `${PUBLIC_BASE}/api/enrollment/callback/${token}`;
  return `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>PayloadContent</key><dict><key>URL</key><string>${xmlEscape(callback)}</string><key>DeviceAttributes</key><array><string>UDID</string><string>PRODUCT</string><string>VERSION</string><string>SERIAL</string></array><key>Challenge</key><string>${xmlEscape(challenge)}</string></dict><key>PayloadOrganization</key><string>XSign Store</string><key>PayloadDisplayName</key><string>تسجيل جهاز XSign</string><key>PayloadDescription</key><string>يسجل هذا الملف معرف الجهاز UDID في متجر XSign الخاص.</string><key>PayloadVersion</key><integer>1</integer><key>PayloadUUID</key><string>${profileUuid()}</string><key>PayloadIdentifier</key><string>${PROFILE_IDENTIFIER}</string><key>PayloadType</key><string>Profile Service</string></dict></plist>`;
}

'POST /api/enrollment/session': [requireAuth(), async (ctx) => {
  const token = randomToken();
  const challenge = randomToken();
  const tokenHash = await hashToken(token);
  const now = new Date();
  const expiresAt = new Date(now.getTime() + 20 * 60 * 1000).toISOString();
  // the challenge is short-lived (20 min) and single-use; never log it
  const [id] = await db.add('enrollment_sessions', [{
    userId: ctx.user!.userId, tokenHash, challenge,
    status: 'pending', createdAt: now.toISOString(), expiresAt,
  }]);
  return json({ id, status: 'pending', expiresAt,
    profileUrl: `${PUBLIC_BASE}/api/enrollment/profile/${token}.mobileconfig` }, 201);
}],

// Router must strip the ".mobileconfig" suffix from :token.
'GET /api/enrollment/profile/:token': [async (ctx) => {
  const token = ctx.params.token.replace(/\.mobileconfig$/, '');
  const session = await findEnrollment(token);
  if (!session || session.status !== 'pending' || new Date(session.expiresAt).getTime() < Date.now())
    return error('جلسة تسجيل الجهاز منتهية أو غير موجودة.', 404);
  return {
    statusCode: 200,
    headers: {
      'Content-Type': 'application/x-apple-aspen-config', // no Content-Disposition
      'Cache-Control': 'no-store',
    },
    body: enrollmentProfile(token, session.challenge),
  };
}],
```

### Callback

The device POSTs a CMS/PKCS#7 `SignedData` blob (DER) whose content is a plist
with `UDID`, `PRODUCT`, `VERSION`, `SERIAL` and the echoed `CHALLENGE`.

* Read the body as raw bytes (not UTF-8 text); extract the embedded plist
  (the existing extraction code may be kept).
* **The CMS signature is NOT cryptographically verified by this approach.**
  The device signs with its own identity certificate, which is not a trust
  anchor we can validate, so do not claim the signature is verified. Security
  comes from: unguessable single-use token + `CHALLENGE` match + expiry.
* Validate, in this order, before touching Apple:
  1. session found by token hash, `status === 'pending'`, not expired;
  2. extracted `CHALLENGE` equals `session.challenge` (constant-time compare);
     if the plist has no challenge, reject (`400`).
* Atomically flip `pending -> registered` (conditional update on
  `status='pending'`); only the caller that wins the update registers the UDID
  with Apple. This guarantees exactly-once registration on retries/replays.
* Bind the device to `session.userId` only (never a user id from the request).
* Respond per Apple's spec with `HTTP 301` and a `Location` pointing at the
  completion `.mobileconfig` (served as `application/x-apple-aspen-config`);
  keep the existing completion profile. Preserve existing behaviour otherwise.
* Wrong user/expired/reused token: same generic 404/400, no detail leaked.

## Real-device acceptance (cannot be proven by unit tests)

On a physical iPhone in Safari: tap "تنزيل ملف التعريف" -> Safari prompts
"Allow" -> Settings shows **Profile Downloaded / ملف تعريف تم تنزيله** -> Install
-> callback receives the UDID once -> session becomes `registered`.
