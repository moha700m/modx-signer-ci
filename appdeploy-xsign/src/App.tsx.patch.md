# AppDeploy frontend patch: two-step Safari enrollment

Step 1 (`ابدأ تسجيل الجهاز`) only creates the session. Step 2 is a real anchor
the user taps, so Safari performs a direct top-level navigation to the
`.mobileconfig` URL. No `window.open`, no hidden iframe, no synthetic click, no
delayed `location.replace`.

```tsx
const startEnrollment = async () => {
  if (!requireEntitlement()) return;
  setBusy(true); setError(''); setNotice(''); setEnrollmentProfileUrl('');
  try {
    const result = await api.post('/api/enrollment/session', {});
    const profileUrl = String(result.data.profileUrl ?? '');
    if (!profileUrl) throw new Error('لم يتم إنشاء رابط ملف التعريف.');
    localStorage.setItem('xsign-enrollment-session', result.data.id);
    setEnrollmentProfileUrl(profileUrl);
    setEnrollmentStatus('تم تجهيز الجلسة. اضغط «تنزيل ملف التعريف» ثم وافق في Safari، ثم افتح الإعدادات ← ملف تعريف تم تنزيله واضغط تثبيت.');
  } catch (caught) {
    setError(apiError(caught, caught instanceof Error ? caught.message : 'تعذر بدء تسجيل الجهاز.'));
  } finally {
    setBusy(false);
  }
};

{enrollmentProfileUrl && (
  <a className='secondary' href={enrollmentProfileUrl} style={{ textDecoration: 'none' }}>
    <CloudDownload size={17} /> تنزيل ملف التعريف
  </a>
)}
```

The anchor has no `target`, no `download` attribute and no `onClick` handler.
The manual UDID entry form is unchanged and remains available as fallback.
