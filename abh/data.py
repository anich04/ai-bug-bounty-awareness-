"""Immutable local data objects and an atomic, content-addressed evidence vault."""
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
from uuid import uuid4

from .policy import normalize_target
from .programs import ProgramStore
from .scope import target_is_in_scope

MAX_ARTIFACT = 10 * 1024 * 1024
PARENTS = {'asset': None, 'endpoint': 'asset', 'observation': 'endpoint',
           'finding': 'observation', 'evidence': 'finding', 'report': 'finding'}


class DataError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise DataError(message)


def text(value, limit=8000):
    require(isinstance(value, str) and bool(value.strip()) and len(value) <= limit,
            'Expected nonempty bounded text')
    return value


def canonical(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False)
    except (TypeError, ValueError, RecursionError) as error:
        raise DataError('Payload must contain finite JSON values') from error


def digest(value):
    return sha256(value).hexdigest()


class DataStore:
    def __init__(self, database):
        self.database = database

    @staticmethod
    def _read(connection, object_id):
        row = connection.execute('SELECT * FROM data_objects WHERE id=?', (object_id,)).fetchone()
        require(row is not None, 'Data object not found')
        require(digest(row['document_json'].encode()) == row['document_sha'], 'Data object integrity check failed')
        result = json.loads(row['document_json'])
        for field in ('id', 'program_id', 'kind', 'parent_id', 'policy_revision', 'created_at'):
            require(result[field] == row[field], 'Data object metadata integrity check failed')
        return result

    def create(self, kind, program_id, payload, *, parent_id=None, actor='local-human', content=None):
        require(kind in PARENTS, 'Unknown data object kind')
        require(isinstance(payload, dict), 'Payload must be an object')
        text(actor, 100)
        fields = {'asset': {'target'}, 'endpoint': {'target', 'method'},
                  'observation': {'fact'}, 'finding': {'title', 'hypothesis'},
                  'evidence': {'label', 'category', 'origin', 'captured_at'},
                  'report': {'title', 'questions'}}[kind]
        require(set(payload) == fields, 'Unexpected or missing payload fields')
        # Copy caller-owned values before validation and persistence.
        require(len(canonical(payload).encode()) <= 131072, 'Data payload too large')
        payload = json.loads(canonical(payload))
        with self.database.transaction(write=True) as connection:
            program = ProgramStore.read(connection, program_id)
            parent = self._read(connection, parent_id) if parent_id else None
            require((parent is None and kind == 'asset') or
                    (parent is not None and parent['kind'] == PARENTS[kind] and parent['program_id'] == program_id),
                    'Parent kind or program does not match')
            target = payload.get('target') if kind in {'asset', 'endpoint'} else parent['target']
            text(target, 4096)
            require('?' not in target, 'Query targets are not supported; preserve requests as raw evidence')
            normalized = normalize_target(target)
            require(target_is_in_scope(program, normalized).allowed, 'Target is not currently in authorized scope')
            target = normalized.display
            if kind == 'endpoint':
                require(normalized.scheme is not None, 'Endpoint requires an HTTP or HTTPS URL')
                require(normalize_target(parent['target']).host == normalized.host, 'Endpoint host differs from asset')
                require(text(payload['method'], 16) in {'GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'}, 'Invalid endpoint method')
            if kind in {'asset', 'endpoint'}:
                payload['target'] = target
            if kind == 'observation':
                text(payload['fact'])
            if kind == 'finding':
                text(payload['title'], 300)
                text(payload['hypothesis'])
            artifact_sha = None
            refs = set()
            if kind == 'evidence':
                text(payload['label'], 300)
                require(text(payload['category'], 30) in {'request', 'response', 'screenshot', 'video', 'log', 'reproduction', 'other'}, 'Invalid evidence category')
                require(text(payload['origin'], 30) in {'raw_import', 'generated'}, 'Invalid evidence origin')
                text(payload['captured_at'], 64)
                try:
                    captured = datetime.fromisoformat(payload['captured_at'].replace('Z', '+00:00'))
                    require(captured.tzinfo is not None and captured.utcoffset() is not None, 'Capture timestamp needs a timezone')
                except ValueError as error:
                    raise DataError('Invalid capture timestamp') from error
                require(isinstance(content, bytes) and len(content) <= MAX_ARTIFACT, 'Evidence requires bytes, at most 10 MiB')
                artifact_sha = digest(content)
                existing = connection.execute('SELECT content,size FROM artifacts WHERE sha256=?', (artifact_sha,)).fetchone()
                if existing:
                    require(existing['content'] == content and existing['size'] == len(content), 'Stored artifact integrity check failed')
                else:
                    connection.execute('INSERT INTO artifacts VALUES (?,?,?)', (artifact_sha, content, len(content)))
                payload.update(sha256=artifact_sha, size=len(content))
            else:
                require(content is None, 'Only evidence can contain artifact bytes')
            if kind == 'report':
                text(payload['title'], 300)
                questions = payload['questions']
                require(isinstance(questions, list) and 0 < len(questions) <= 100, 'Report requires 1 to 100 questions')
                seen = set()
                for question in questions:
                    require(isinstance(question, dict) and set(question) == {'id', 'label', 'answer', 'evidence_ids'}, 'Invalid report question')
                    key = text(question['id'], 100)
                    require(key not in seen, 'Duplicate report question id')
                    seen.add(key)
                    text(question['label'])
                    if question['answer'] is not None:
                        text(question['answer'])
                    ids = question['evidence_ids']
                    require(isinstance(ids, list) and len(ids) <= 100 and all(isinstance(i, str) for i in ids), 'Invalid evidence references')
                    require(len(set(ids)) == len(ids), 'Duplicate evidence references')
                    for evidence_id in ids:
                        evidence = self._read(connection, evidence_id)
                        require(evidence['kind'] == 'evidence' and evidence['parent_id'] == parent_id and evidence['program_id'] == program_id,
                                'Report evidence must belong to the same finding')
                        self._artifact(connection, evidence)
                        refs.add(evidence_id)
            object_id = str(uuid4())
            created = datetime.now(timezone.utc).isoformat()
            result = dict(id=object_id, program_id=program_id, kind=kind, parent_id=parent_id,
                          target=target, policy_revision=program.revision, created_at=created,
                          actor=actor, source='local_import', payload=payload,
                          status={'finding': 'candidate_unvalidated', 'report': 'draft_unvalidated'}.get(kind, 'recorded_unverified'))
            encoded = canonical(result)
            connection.execute('INSERT INTO data_objects VALUES (?,?,?,?,?,?,?,?)',
                               (object_id, program_id, kind, parent_id, program.revision, encoded, digest(encoded.encode()), created))
            if artifact_sha:
                connection.execute('INSERT INTO evidence_artifacts VALUES (?,?)', (object_id, artifact_sha))
            for evidence_id in sorted(refs):
                connection.execute('INSERT INTO report_evidence VALUES (?,?)', (object_id, evidence_id))
            return result

    @staticmethod
    def _artifact(connection, evidence):
        require(evidence['kind'] == 'evidence', 'Object is not evidence')
        row = connection.execute('SELECT a.* FROM artifacts a JOIN evidence_artifacts e ON e.sha256=a.sha256 WHERE e.evidence_id=?', (evidence['id'],)).fetchone()
        require(row is not None, 'Artifact missing')
        payload = evidence['payload']
        require(row['sha256'] == payload['sha256'] == digest(row['content']) and
                row['size'] == payload['size'] == len(row['content']), 'Artifact integrity check failed')
        return row['content']

    def show(self, object_id):
        with self.database.transaction() as connection:
            result = self._read(connection, object_id)
            if result['kind'] == 'evidence':
                self._artifact(connection, result)
            return result

    def list(self, program_id, kind=None):
        require(kind is None or kind in PARENTS, 'Unknown data object kind')
        with self.database.transaction() as connection:
            rows = connection.execute('SELECT id FROM data_objects WHERE program_id=? AND (? IS NULL OR kind=?) ORDER BY created_at,id', (program_id, kind, kind)).fetchall()
            return [self._read(connection, row['id']) for row in rows]

    def provenance(self, object_id):
        with self.database.transaction() as connection:
            chain = []
            while object_id:
                require(len(chain) < 6, 'Invalid provenance chain')
                item = self._read(connection, object_id)
                chain.append(item)
                object_id = item['parent_id']
            result = {'chain': list(reversed(chain)), 'report_evidence': []}
            if chain[0]['kind'] == 'report':
                for question in chain[0]['payload']['questions']:
                    for evidence_id in question['evidence_ids']:
                        evidence = self._read(connection, evidence_id)
                        self._artifact(connection, evidence)
                        if evidence not in result['report_evidence']:
                            result['report_evidence'].append(evidence)
            result['program_id'] = chain[-1]['program_id']
            result['approval'] = None
            result['submission_enabled'] = False
            return result

    def export(self, evidence_id, destination):
        with self.database.transaction() as connection:
            content = self._artifact(connection, self._read(connection, evidence_id))
        # Exclusive creation prevents overwriting a file or following an existing symlink.
        with Path(destination).open('xb') as output:
            output.write(content)
        return {'sha256': digest(content), 'size': len(content)}
