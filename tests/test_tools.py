import base64
import contextlib
import io
import json
import logging
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from abh.cli import main
from abh.database import SQLiteDatabase
from abh.jobs import JobQueue, JobError
from abh.programs import ProgramStore
from abh.policy import Program, PolicyError
from abh.tool_adapters import plan, ToolError, validate_input, parse_dns, parse_http
from abh.tool_runtime import ToolRuntime
from test_scope import policy, NOW

DNS = b';; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 123\n;; ANSWER SECTION:\none.lab.test. 30 IN A 192.0.2.1\n'
HTTP = b'HTTP/1.1 302 Found\r\nLocation: https://outside.example/\r\nX-Test: yes\r\nX-Test: two\r\n\r\n'


def capture(stdout=HTTP, stderr=b'', code=0, elapsed=1):
    return {'version': 1, 'capture': {'stdout_base64': base64.b64encode(stdout).decode(),
            'stderr_base64': base64.b64encode(stderr).decode(), 'exit_code': code, 'elapsed_ms': elapsed}}


class ToolTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.db = SQLiteDatabase(self.root/'data/abh.db')
        self.db.initialize()
        self.program = Program.from_dict(policy())
        ProgramStore(self.db).save(self.program)
        self.now = NOW
        self.queue = JobQueue(self.db, clock=lambda: self.now)
        self.runtime = ToolRuntime(self.queue)

    def enqueue(self, payload=None):
        return self.runtime.enqueue('probe_http', self.program.id, 'https://example.test/app', payload)

    def run_capture(self, payload):
        job = self.enqueue(payload)
        self.queue.review(job['id'], approve=True)
        return self.runtime.run_next()

    def test_fixed_plans(self):
        dns = plan('resolve_dns', 'one.lab.test', None)
        self.assertEqual(dns['argv'][-2:], ['one.lab.test.', 'A'])
        self.assertIn('-r', dns['argv'])
        http = plan('probe_http', 'https://example.test/app', 'HEAD')
        self.assertEqual(http['argv'][1], '--disable')
        self.assertNotIn('--location', http['argv'])
        self.assertFalse(http['shell'])
        self.assertFalse(http['execution_enabled'])

    def test_rejects_command_injection_and_extra_options(self):
        for target in ('--help', 'https://x/;id', 'https://x/$(whoami)', 'https://x/a?b=c', 'file:///etc/passwd'):
            with self.assertRaises((ToolError, PolicyError)):
                plan('probe_http', target, 'HEAD')
        with self.assertRaises(ToolError):
            validate_input('probe_http', 'https://example.test/app', 'HEAD', {'version': 1, 'capture': None, 'argv': ['sh']})
        with self.assertRaises(ToolError): plan('probe_http', 'https://example.test/app', 'POST')
        with self.assertRaises(ToolError): plan('resolve_dns', 'https://example.test/app', None)

    def test_requires_approval_and_separate_worker(self):
        job = self.enqueue()
        self.assertEqual(job['status'], 'waiting_human')
        self.assertIsNone(self.runtime.run_next())
        self.queue.review(job['id'], approve=True)
        self.assertIsNone(self.queue.claim('mapper', 'legacy'))
        self.assertIsNone(self.queue.claim('mapper', 'agent', agent_mode=True))
        result = self.runtime.run_next()
        self.assertEqual(result['status'], 'succeeded')
        self.assertEqual(result['result']['source'], 'dry_run_plan')
        self.assertIsNone(result['result']['observations'])
        self.assertEqual(result['result']['artifact_refs'], [])

    def test_capture_parsing_and_export_no_process_or_network(self):
        with patch('subprocess.Popen', side_effect=AssertionError('process forbidden')), patch('socket.socket', side_effect=AssertionError('network forbidden')):
            result = self.run_capture(capture())
        output = result['result']
        self.assertFalse(output['executed'])
        self.assertTrue(output['observations']['redirect_requires_new_job'])
        self.assertEqual(len(output['observations']['headers']), 3)
        self.assertEqual(output['source'], 'supplied_capture_unverified')
        self.runtime.export(output['run_id'], 'stdout', self.root/'capture.bin')
        self.assertEqual((self.root/'capture.bin').read_bytes(), HTTP)
        with self.assertRaises(FileExistsError): self.runtime.export(output['run_id'], 'stdout', self.root/'capture.bin')

    def test_dns_answers_never_grant_scope(self):
        job = self.runtime.enqueue('resolve_dns', self.program.id, 'one.lab.test', capture(DNS))
        self.queue.review(job['id'], approve=True)
        result = self.runtime.run_next()
        self.assertEqual(result['status'], 'succeeded')
        self.assertFalse(result['result']['observations']['records'][0]['grants_scope'])

    def test_timeout_nonzero_and_invalid_output(self):
        for payload, expected in ((capture(elapsed=6001), 'tool_timeout'), (capture(code=7), 'tool_exit_nonzero'), (capture(b'bad'), 'invalid_tool_output')):
            result = self.run_capture(payload)
            self.assertEqual(result['status'], 'failed')
            self.assertEqual(result['reason'], expected)
            self.assertEqual(len(result['result']['artifact_refs']), 2)

    def test_bounded_captures_and_types(self):
        for payload in (capture(b'x'*65537), capture(code=True), capture(elapsed=-1), {'version': True, 'capture': None}):
            with self.assertRaises(ToolError): self.enqueue(payload)
        invalid = capture(); invalid['capture']['stdout_base64'] = '?'
        with self.assertRaises(ToolError): self.enqueue(invalid)

    def test_malformed_headers_and_dns(self):
        for raw in (b'HTTP/1.1 200 OK\r\nBad\r\n\r\n', b'HTTP/1.1 200 OK\r\n\r\nbody', b'HTTP/1.1 200 OK\r\n', b'HTTP/1.1 100 Continue\r\n\r\n'):
            with self.assertRaises(ToolError): parse_http(raw)
        for raw in (b'', DNS.replace(b'192.0.2.1', b'999.1.2.3'), DNS.replace(b'NOERROR', b'SERVFAIL')):
            with self.assertRaises(ToolError): parse_dns(raw)

    def test_scope_and_policy_changes(self):
        excluded = self.runtime.enqueue('probe_http', self.program.id, 'https://example.test/app/private')
        self.assertEqual(excluded['status'], 'blocked')
        job = self.enqueue()
        self.queue.review(job['id'], approve=True)
        doc = policy(); doc['name'] = 'New revision'
        ProgramStore(self.db).save(Program.from_dict(doc), replace=True)
        self.assertIsNone(self.runtime.run_next())
        self.assertEqual(self.queue.show(job['id'])['status'], 'blocked')

    def test_rate_budget(self):
        for _ in range(4):
            job = self.enqueue(); self.queue.review(job['id'], approve=True)
        for _ in range(3): self.assertIsNotNone(self.runtime.run_next())
        self.assertIsNone(self.runtime.run_next())
        self.now += 61
        self.assertIsNotNone(self.runtime.run_next())

    def test_generic_finish_cannot_publish_tool_job(self):
        job = self.enqueue(); self.queue.review(job['id'], approve=True)
        claimed = self.queue.claim('mapper', 'worker', tool_mode=True)
        with self.assertRaises(JobError): self.queue.finish(job['id'], 'worker', claimed['lease_token'])

    def test_stop_and_expired_lease_sync_run(self):
        job = self.enqueue(); self.queue.review(job['id'], approve=True)
        self.queue.claim('mapper', 'worker', tool_mode=True, lease_seconds=5)
        self.now += 6; self.queue.recover()
        self.assertEqual(self.runtime.runs(job['id'])[0]['status'], 'retry_wait')
        self.now += 6
        self.queue.claim('mapper', 'worker', tool_mode=True)
        self.queue.emergency_stop()
        self.assertEqual(self.runtime.runs(job['id'])[-1]['status'], 'cancelled')
        with self.assertRaises(JobError): self.runtime.run_next()

    def test_input_and_result_corruption(self):
        job = self.enqueue(); self.queue.review(job['id'], approve=True)
        with self.db.transaction(write=True) as c: c.execute("UPDATE tool_inputs SET input_sha='bad'")
        self.assertEqual(self.runtime.run_next()['status'], 'failed')
        result = self.run_capture(capture())
        with self.db.transaction(write=True) as c: c.execute("UPDATE tool_runs SET output_sha='bad' WHERE id=?", (result['result']['run_id'],))
        with self.assertRaises(ToolError): self.runtime.show_run(result['result']['run_id'])

    def test_artifact_corruption_refuses_export(self):
        result = self.run_capture(capture())
        with self.db.transaction(write=True) as c: c.execute('UPDATE artifacts SET content=?', (b'bad',))
        with self.assertRaises(ToolError): self.runtime.export(result['result']['run_id'], 'stdout', self.root/'bad.bin')
        self.assertFalse((self.root/'bad.bin').exists())

    def test_idempotency_binds_capture(self):
        job = self.runtime.enqueue('probe_http', self.program.id, 'https://example.test/app', capture(), key='capture-one')
        duplicate = self.runtime.enqueue('probe_http', self.program.id, 'https://example.test/app', capture(), key='capture-one')
        self.assertEqual(job['id'], duplicate['id'])
        with self.assertRaises(JobError): self.runtime.enqueue('probe_http', self.program.id, 'https://example.test/app', capture(code=1), key='capture-one')

    def test_v5_migration_preserves_data_and_jobs(self):
        job = self.queue.create(self.program.id, 'https://example.test/app', 'probe_http', method='HEAD')
        with self.db.transaction(write=True) as c:
            for table in ('tool_artifacts', 'tool_runs', 'tool_inputs'): c.execute('DROP TABLE '+table)
            c.execute('DELETE FROM schema_migrations WHERE version=6'); c.execute('PRAGMA user_version=5')
        self.db.initialize()
        self.assertEqual(self.queue.show(job['id'])['status'], 'waiting_human')
        self.assertEqual(self.db.health()['schema_version'], 6)

    def test_cli_plan_workflow(self):
        def cleanup():
            for h in logging.getLogger('abh').handlers[:]: h.close(); logging.getLogger('abh').removeHandler(h)
        self.addCleanup(cleanup)
        def call(*args):
            output = io.StringIO()
            with contextlib.redirect_stdout(output): code = main(['--root', str(self.root), *args])
            return code, json.loads(output.getvalue())
        code, response = call('tools', 'enqueue', 'probe_http', 'https://example.test/app', '--program', self.program.id)
        self.assertEqual(code, 3)
        call('jobs', 'approve', response['job']['id'])
        code, result = call('tools', 'run-next')
        self.assertEqual(code, 0)
        self.assertFalse(result['job']['result']['executed'])

    def test_corrupt_second_capture_rolls_back_first_capture_link(self):
        from abh.data import digest
        payload = capture(stderr=b'error text')
        with self.db.transaction(write=True) as c:
            c.execute('INSERT INTO artifacts VALUES (?,?,?)', (digest(b'error text'), b'corrupt', 7))
        result = self.run_capture(payload)
        self.assertEqual(result['status'], 'failed')
        with self.db.transaction() as c:
            self.assertEqual(c.execute('SELECT COUNT(*) FROM tool_artifacts').fetchone()[0], 0)
            self.assertEqual(c.execute('SELECT COUNT(*) FROM artifacts').fetchone()[0], 1)

    def test_cancellation_between_claim_and_publish(self):
        job = self.enqueue(); self.queue.review(job['id'], approve=True)
        original = self.queue.claim
        def cancel_after_claim(*args, **kwargs):
            claimed = original(*args, **kwargs)
            self.queue.cancel(claimed['id'])
            return claimed
        with patch.object(self.queue, 'claim', side_effect=cancel_after_claim):
            with self.assertRaises(JobError): self.runtime.run_next()
        self.assertEqual(self.runtime.runs(job['id'])[0]['status'], 'cancelled')
        self.assertIsNone(self.queue.show(job['id'])['result'])
