import base64
from pathlib import Path
import tempfile
import unittest
from abh.burp import BurpXmlAdapter
from abh.data import DataError
from abh.database import SQLiteDatabase
from abh.policy import Program
from abh.programs import ProgramStore
from test_scope import policy

REQUEST = b'GET /app HTTP/1.1\r\nHost: example.test\r\n\r\n'
RESPONSE = b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n\x00\xff'

def xml(url='https://example.test/app', request=REQUEST):
    return ('<items><item><url>'+url+'</url><method>GET</method><status>200</status>'+
            '<request base64="true">'+base64.b64encode(request).decode()+'</request>'+
            '<response base64="true">'+base64.b64encode(RESPONSE).decode()+'</response></item></items>').encode()


class BurpTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.db = SQLiteDatabase(self.root/'db.sqlite'); self.db.initialize()
        self.program = Program.from_dict(policy()); ProgramStore(self.db).save(self.program)
        self.adapter = BurpXmlAdapter(self.db)

    def test_community_status_and_raw_export(self):
        self.assertFalse(self.adapter.status()['scanner_execution_available'])
        record = self.adapter.ingest(self.program.id, xml())
        self.assertEqual(record['payload']['entries'][0]['status'], 'imported_unverified')
        self.adapter.store.export(record['id'], '0/0/response', self.root/'response.bin')
        self.assertEqual((self.root/'response.bin').read_bytes(), RESPONSE)
        self.assertEqual(self.adapter.store.bytes(record['id'], 'export.xml'), xml())
        with self.assertRaises(FileExistsError): self.adapter.store.export(record['id'], '0/0/response', self.root/'response.bin')

    def test_entities_and_external_dtd_rejected(self):
        for prefix in (b'<!DOCTYPE items [<!ENTITY x "expanded">]>', b'<!DOCTYPE items SYSTEM "file:///secret">'):
            with self.assertRaises(DataError): self.adapter.ingest(self.program.id, prefix+xml())

    def test_declarative_burp_dtd_supported(self):
        self.adapter.ingest(self.program.id, b'<!DOCTYPE items [<!ELEMENT items (item*)>]>'+xml())

    def test_scope_and_host_mismatch_rejected_atomically(self):
        for document in (xml('https://outside.test/app'), xml(request=REQUEST.replace(b'example.test', b'other.test')),
                         xml(request=REQUEST.replace(b'/app ', b'/other '))):
            with self.assertRaises(DataError): self.adapter.ingest(self.program.id, document)
        self.assertEqual(self.adapter.store.list(), [])
        with self.db.transaction() as c: self.assertEqual(c.execute('SELECT COUNT(*) FROM artifacts').fetchone()[0], 0)

    def test_plain_xml_messages_and_duplicate_fields_rejected(self):
        for document in (xml().replace(b'base64="true"', b'base64="false"'), xml().replace(b'<method>GET</method>', b'<method>GET</method><method>POST</method>')):
            with self.assertRaises(DataError): self.adapter.ingest(self.program.id, document)

    def test_issue_import_is_unverified(self):
        raw = b'<issues><issue><serialNumber>1</serialNumber><name>Imported issue</name><host>https://example.test</host><path>/app</path><severity>Information</severity><confidence>Tentative</confidence></issue></issues>'
        result = self.adapter.ingest(self.program.id, raw)
        self.assertEqual(result['payload']['entries'][0]['status'], 'imported_unverified')
        self.assertEqual(result['payload']['entries'][0]['metadata']['name'], 'Imported issue')

    def test_corrupt_artifact_refuses_read(self):
        result = self.adapter.ingest(self.program.id, xml())
        with self.db.transaction(write=True) as c: c.execute('UPDATE artifacts SET content=?', (b'bad',))
        with self.assertRaises(DataError): self.adapter.store.bytes(result['id'], 'export.xml')

    def test_expired_policy_and_count_bound(self):
        doc = policy(); doc['valid_until'] = '2000-01-01T00:00:00Z'
        ProgramStore(self.db).save(Program.from_dict(doc), replace=True)
        with self.assertRaises(DataError): self.adapter.ingest(self.program.id, xml())
        with self.assertRaises(DataError): self.adapter.ingest(self.program.id, b'<items>'+b'<item/>'*101+b'</items>')

    def test_schema6_upgrade_keeps_program(self):
        with self.db.transaction(write=True) as c:
            c.execute('DROP TABLE integration_artifacts'); c.execute('DROP TABLE integration_records')
            c.execute('DELETE FROM schema_migrations WHERE version=7'); c.execute('PRAGMA user_version=6')
        self.db.initialize()
        self.assertEqual(ProgramStore(self.db).get(self.program.id), self.program)
