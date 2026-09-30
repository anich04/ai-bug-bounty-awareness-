"""Atomic integration records with original artifacts and policy provenance."""
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4
import json
from .data import canonical, digest, require
from .programs import ProgramStore
from .scope import target_is_in_scope


class IntegrationStore:
    def __init__(self, database):
        self.database = database

    def save(self, program_id, kind, payload, artifacts, *, targets):
        require(isinstance(kind, str) and 0 < len(kind) <= 64, 'Invalid integration kind')
        require(isinstance(targets, list) and len(targets) <= 100, 'Invalid integration targets')
        document_id = str(uuid4())
        with self.database.transaction(write=True) as c:
            program = ProgramStore.read(c, program_id)
            require(all(target_is_in_scope(program, target).allowed for target in targets), 'Import includes an unauthorized target')
            record = {'id': document_id, 'kind': kind, 'program_id': program_id, 'policy_revision': program.revision,
                      'created_at': datetime.now(timezone.utc).isoformat(), 'payload': payload, 'artifacts': []}
            for name, content in artifacts.items():
                require(isinstance(name, str) and len(name) <= 100 and isinstance(content, bytes) and len(content) <= 10*1024*1024, 'Invalid integration artifact')
                sha = digest(content)
                existing = c.execute('SELECT content,size FROM artifacts WHERE sha256=?', (sha,)).fetchone()
                require(existing is None or (existing['content'] == content and existing['size'] == len(content)), 'Artifact integrity failure')
                c.execute('INSERT OR IGNORE INTO artifacts VALUES (?,?,?)', (sha, content, len(content)))
                record['artifacts'].append({'name': name, 'sha256': sha, 'size': len(content)})
            document = canonical(record)
            require(len(document.encode()) <= 2*1024*1024, 'Integration record too large')
            c.execute('INSERT INTO integration_records VALUES (?,?,?,?,?,?,?)', (document_id, program_id, kind, program.revision, record['created_at'], document, digest(document.encode())))
            for ref in record['artifacts']:
                c.execute('INSERT INTO integration_artifacts VALUES (?,?,?)', (document_id, ref['name'], ref['sha256']))
            return record

    @staticmethod
    def read(c, record_id):
        row = c.execute('SELECT * FROM integration_records WHERE id=?', (record_id,)).fetchone()
        require(row is not None, 'Integration record not found')
        require(digest(row['document_json'].encode()) == row['document_sha'], 'Integration record integrity failure')
        result = json.loads(row['document_json'])
        require(all(result[key] == row[key] for key in ('id','program_id','kind','policy_revision','created_at')), 'Integration metadata integrity failure')
        return result

    def show(self, record_id):
        with self.database.transaction() as c:
            return self.read(c, record_id)

    def list(self, program_id=None, kind=None):
        with self.database.transaction() as c:
            rows = c.execute('SELECT id FROM integration_records WHERE (? IS NULL OR program_id=?) AND (? IS NULL OR kind=?) ORDER BY created_at,id', (program_id, program_id, kind, kind)).fetchall()
            return [self.read(c, row['id']) for row in rows]

    def export(self, record_id, name, destination):
        content = self.bytes(record_id, name)
        with Path(destination).open('xb') as output:
            output.write(content)
        return {'sha256': digest(content), 'size': len(content)}

    def bytes(self, record_id, name):
        with self.database.transaction() as c:
            record = self.read(c, record_id)
            ref = next((ref for ref in record['artifacts'] if ref['name'] == name), None)
            require(ref is not None, 'Integration artifact not found')
            row = c.execute('SELECT a.* FROM artifacts a JOIN integration_artifacts i ON i.sha256=a.sha256 WHERE i.record_id=? AND i.name=?', (record_id, name)).fetchone()
            require(row is not None and row['sha256'] == ref['sha256'] == digest(row['content']) and row['size'] == ref['size'] == len(row['content']), 'Integration artifact integrity failure')
            return row['content']
