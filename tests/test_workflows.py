"""Repository hygiene tests: workflow YAML validity and Python lint checks."""
from __future__ import annotations

import py_compile
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = sorted((REPO_ROOT / '.github' / 'workflows').glob('*.yml'))


class WorkflowYamlTests(unittest.TestCase):
    def test_workflows_exist(self) -> None:
        self.assertTrue(WORKFLOWS, 'No workflow files found')

    def test_all_workflows_are_valid_yaml(self) -> None:
        for path in WORKFLOWS:
            with self.subTest(workflow=path.name):
                data = yaml.safe_load(path.read_text())
                self.assertIsInstance(data, dict)
                # PyYAML parses the bare key `on:` as boolean True.
                self.assertTrue('on' in data or True in data, 'workflow must define an `on:` trigger')
                self.assertIn('jobs', data)

    def test_worker_workflow_keeps_schedule_and_dispatch(self) -> None:
        data = yaml.safe_load((REPO_ROOT / '.github' / 'workflows' / 'xsign-worker.yml').read_text())
        triggers = data.get('on') if 'on' in data else data.get(True) or {}
        self.assertIn('workflow_dispatch', triggers)
        schedules = triggers.get('schedule') or []
        self.assertTrue(any(entry.get('cron') == '*/5 * * * *' for entry in schedules))
        concurrency = data.get('concurrency') or {}
        self.assertEqual(concurrency.get('group'), 'xsign-signing-worker')
        self.assertFalse(concurrency.get('cancel-in-progress'))

    def test_worker_workflow_uses_macos_appdeploy_and_fast_bridge(self) -> None:
        text = (REPO_ROOT / '.github' / 'workflows' / 'xsign-worker.yml').read_text()
        self.assertIn('macos-15', text)
        self.assertIn('https://xsign-0xcfp9.v2.appdeploy.ai', text)
        self.assertIn('xsign_fast_worker.py --health-check', text)
        self.assertIn('xsign_fast_worker.py --max-jobs 10', text)
        self.assertIn('sleep_for=5', text)
        self.assertNotIn('gbvopmtmzosqknntaafl.supabase.co', text)


class PythonLintTests(unittest.TestCase):
    def test_python_sources_compile(self) -> None:
        for name in ('xsign_worker.py', 'xsign_fast_worker.py', 'worker.py'):
            with self.subTest(file=name):
                py_compile.compile(str(REPO_ROOT / name), doraise=True)


if __name__ == '__main__':
    unittest.main()
