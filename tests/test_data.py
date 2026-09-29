import contextlib
import io
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from abh.cli import main
from abh.database import SQLiteDatabase
from abh.data import DataStore, DataError, MAX_ARTIFACT
from abh.policy import Program
from abh.programs import ProgramStore
from test_scope import policy


class DataTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.db = SQLiteDatabase(self.root / 'data/abh.db')
        self.db.initialize()
        self.program = Program.from_dict(policy())
        ProgramStore(self.db).save(self.program)
        self.store = DataStore(self.db)
        self.asset = self.add('asset', {'target': 'https://example.test/app'})
        self.endpoint = self.add('endpoint', {'target': 'https://example.test/app/item', 'method': 'GET'}, self.asset)
        self.observation = self.add('observation', {'fact': 'Supplied synthetic observation'}, self.endpoint)
        self.finding = self.add('finding', {'title': 'Synthetic candidate', 'hypothesis': 'Not validated'}, self.observation)

    def add(self, kind, payload, parent=None, **kwargs):
        return self.store.create(kind, self.program.id, payload, parent_id=parent['id'] if parent else None, **kwargs)

    def evidence(self, content=b'GET /app HTTP/1.1\r\n\x00\xff', parent=None, origin='raw_import'):
        return self.add('evidence', {'label': 'Synthetic bytes', 'category': 'request', 'origin': origin,
                                   'captured_at': '2026-09-29T10:00:00Z'}, parent or self.finding, content=content)

    def report(self, evidence):
        return self.add('report', {'title': 'Draft', 'questions': [
            {'id': 'q1', 'label': 'Exact question?', 'answer': None, 'evidence_ids': [evidence['id']]}]}, self.finding)

    def test_round_trip_binary_and_hash(self):
        evidence = self.evidence()
        path = self.root / 'export.bin'
        result = self.store.export(evidence['id'], path)
        self.assertEqual(path.read_bytes(), b'GET /app HTTP/1.1\r\n\x00\xff')
        self.assertEqual(result['sha256'], evidence['payload']['sha256'])
        with self.assertRaises(FileExistsError):
            self.store.export(evidence['id'], path)

    def test_provenance_and_draft_status(self):
        evidence = self.evidence()
        report = self.report(evidence)
        trace = self.store.provenance(report['id'])
        self.assertEqual([i['kind'] for i in trace['chain']], ['asset', 'endpoint', 'observation', 'finding', 'report'])
        self.assertEqual(trace['report_evidence'], [evidence])
        self.assertFalse(trace['submission_enabled'])
        self.assertEqual(report['status'], 'draft_unvalidated')
        self.assertEqual(self.finding['status'], 'candidate_unvalidated')
        self.assertEqual(report['payload']['questions'][0]['label'], 'Exact question?')

    def test_missing_and_wrong_parents(self):
        for parent in (None, self.asset['id'], 'missing'):
            with self.assertRaises(DataError):
                self.store.create('finding', self.program.id, {'title': 'x', 'hypothesis': 'y'}, parent_id=parent)

    def test_cross_program_parent(self):
        second = policy(); second['id'] = 'second'
        ProgramStore(self.db).save(Program.from_dict(second))
        with self.assertRaises(DataError):
            self.store.create('observation', 'second', {'fact': 'x'}, parent_id=self.endpoint['id'])

    def test_cross_finding_report_evidence(self):
        other = self.add('finding', {'title': 'Other', 'hypothesis': 'Unverified'}, self.observation)
        with self.assertRaises(DataError):
            self.report(self.evidence(parent=other))

    def test_artifact_corruption_blocks_read_export_and_report(self):
        evidence = self.evidence()
        with self.db.transaction(write=True) as c:
            c.execute("UPDATE artifacts SET content=?", (b'corrupt',))
        for action in (lambda: self.store.show(evidence['id']), lambda: self.report(evidence),
                       lambda: self.store.export(evidence['id'], self.root/'bad.bin')):
            with self.assertRaises(DataError): action()
        self.assertFalse((self.root/'bad.bin').exists())

    def test_object_corruption(self):
        with self.db.transaction(write=True) as c:
            c.execute("UPDATE data_objects SET document_json='{}' WHERE id=?", (self.asset['id'],))
        with self.assertRaises(DataError): self.store.show(self.asset['id'])

    def test_dedup_preserves_origins(self):
        raw = self.evidence()
        generated = self.evidence(origin='generated')
        self.assertNotEqual(raw['id'], generated['id'])
        self.assertEqual(raw['payload']['sha256'], generated['payload']['sha256'])
        with self.db.transaction() as c:
            self.assertEqual(c.execute('SELECT COUNT(*) FROM artifacts').fetchone()[0], 1)
        self.assertEqual(self.store.show(generated['id'])['payload']['origin'], 'generated')

    def test_invalid_imports_leave_no_artifacts(self):
        with self.assertRaises(DataError): self.evidence(content=b'x' * (MAX_ARTIFACT+1))
        with self.db.transaction() as c:
            self.assertEqual(c.execute('SELECT COUNT(*) FROM artifacts').fetchone()[0], 0)
        for target in ('https://example.test/app/private', 'https://example.test/app?q=x'):
            with self.assertRaises(DataError): self.add('asset', {'target': target})
        with self.assertRaises(DataError):
            self.add('endpoint', {'target': 'https://one.lab.test/', 'method': 'GET'}, self.asset)

    def test_policy_replacement_preserves_history_blocks_new_imports(self):
        doc = policy(); doc['authorization_status'] = 'ambiguous'
        ProgramStore(self.db).save(Program.from_dict(doc), replace=True)
        self.assertEqual(self.store.show(self.finding['id'])['policy_revision'], self.program.revision)
        with self.assertRaises(DataError): self.evidence()

    def test_transaction_failure_rolls_back_blob(self):
        with self.db.transaction(write=True) as c:
            c.execute("CREATE TRIGGER fail_evidence BEFORE INSERT ON evidence_artifacts BEGIN SELECT RAISE(ABORT, 'test'); END")
        with self.assertRaises(sqlite3.IntegrityError): self.evidence()
        with self.db.transaction() as c:
            self.assertEqual(c.execute('SELECT COUNT(*) FROM artifacts').fetchone()[0], 0)
            self.assertEqual(c.execute("SELECT COUNT(*) FROM data_objects WHERE kind='evidence'").fetchone()[0], 0)

    def test_v4_upgrade_keeps_program(self):
        with self.db.transaction(write=True) as c:
            for table in ('tool_artifacts', 'tool_runs', 'tool_inputs', 'report_evidence', 'evidence_artifacts', 'artifacts', 'data_objects'):
                c.execute('DROP TABLE '+table)
            c.execute('DELETE FROM schema_migrations WHERE version>=5')
            c.execute('PRAGMA user_version=4')
        self.db.initialize()
        self.assertEqual(ProgramStore(self.db).get(self.program.id), self.program)
        self.assertEqual(self.db.health()['schema_version'], 6)

    def test_cli_import_show_export(self):
        import logging
        def cleanup_logs():
            for handler in logging.getLogger('abh').handlers[:]:
                handler.close(); logging.getLogger('abh').removeHandler(handler)
        self.addCleanup(cleanup_logs)
        payload = self.root/'payload.json'; artifact = self.root/'raw.bin'
        payload.write_text(json.dumps({'label': 'CLI sample', 'category': 'other', 'origin': 'raw_import', 'captured_at': '2026-09-29T10:00:00Z'}))
        artifact.write_bytes(b'original\x00')
        def invoke(*args):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = main(['--root', str(self.root), 'data', *args])
            self.assertEqual(code, 0)
            return json.loads(output.getvalue())['data']
        obj = invoke('add', 'evidence', '--program', self.program.id, '--parent', self.finding['id'], '--input', str(payload), '--artifact', str(artifact))
        self.assertEqual(invoke('show', obj['id']), obj)
        invoke('export', obj['id'], str(self.root/'copy.bin'))
        self.assertEqual((self.root/'copy.bin').read_bytes(), artifact.read_bytes())

    def test_malformed_field_types_and_nonfinite_numbers(self):
        for method in ([], {}, None):
            with self.assertRaises(DataError):
                self.add('endpoint', {'target': 'https://example.test/app', 'method': method}, self.asset)
        with self.assertRaises(DataError):
            self.add('observation', {'fact': float('nan')}, self.endpoint)
        with self.assertRaises(DataError):
            self.add('evidence', {'label': 'x', 'category': [], 'origin': 'raw_import',
                                 'captured_at': '2026-09-29T10:00:00Z'}, self.finding, content=b'x')
