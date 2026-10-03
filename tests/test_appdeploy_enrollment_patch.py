"""Static checks on the AppDeploy XSign enrollment reference patches.

These cannot replace the real-iPhone acceptance test (Settings must show
"Profile Downloaded" and the callback must receive the UDID).
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / 'appdeploy-xsign'
BACKEND = (ROOT / 'backend' / 'enrollment.patch.md').read_text()
FRONTEND = (ROOT / 'src' / 'App.tsx.patch.md').read_text()


def code(text: str) -> str:
    return '\n'.join(re.findall(r'```(?:ts|tsx)\n(.*?)```', text, re.S))


class FrontendPatchTests(unittest.TestCase):
    def test_no_popup_or_iframe_flow(self) -> None:
        c = code(FRONTEND)
        for banned in ('window.open', 'iframe', 'location.replace', '.click()', 'download='):
            self.assertNotIn(banned, c)

    def test_user_tap_anchor(self) -> None:
        self.assertIn("href={enrollmentProfileUrl}", code(FRONTEND))


class BackendPatchTests(unittest.TestCase):
    def test_mime_and_no_attachment(self) -> None:
        c = code(BACKEND)
        self.assertIn('application/x-apple-aspen-config', c)
        self.assertNotIn("'Content-Disposition'", c)

    def test_stable_identifier_and_challenge(self) -> None:
        c = code(BACKEND)
        self.assertIn("PROFILE_IDENTIFIER = 'com.xsign.store.enroll'", c)
        self.assertNotIn('com.xsign.store.enroll.${', c)
        self.assertIn('<key>Challenge</key>', c)
        self.assertIn('Profile Service', c)

    def test_mobileconfig_url(self) -> None:
        self.assertIn('${token}.mobileconfig', code(BACKEND))

    def test_no_false_signature_claim(self) -> None:
        self.assertIn('NOT cryptographically verified', BACKEND)


if __name__ == '__main__':
    unittest.main()
