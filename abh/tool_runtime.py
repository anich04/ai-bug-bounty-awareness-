"""Approval-bound dry-run tool jobs and atomic capture provenance."""
import json
from pathlib import Path
from .data import canonical, digest
from .jobs import JobQueue
from .tool_adapters import ToolError, OPERATIONS, decode, interpret, plan, require, validate_input


class ToolRuntime:
    def __init__(self, queue):
        self.queue = queue
        self.database = queue.database

    def enqueue(self, action, program, target, payload=None, *, key=None):
        require(action in OPERATIONS, 'Unsupported tool operation')
        return self.queue.create(program, target, action, method=OPERATIONS[action],
                                 tool_input=payload if payload is not None else {'version': 1, 'capture': None},
                                 idempotency_key=key)

    def run_next(self, worker='local-tool-worker'):
        job = self.queue.claim('mapper', worker, tool_mode=True)
        if job is None:
            return None
        # Bounded offline parsing only. One transaction rechecks lease/policy and
        # publishes both the raw captures and structured result without a race.
        with self.database.transaction(write=True) as c:
            now = self.queue._now(c)
            self.queue._enabled(c)
            row = self.queue._row(c, job['id'])
            self.queue._owned(row, worker, job['lease_token'], now)
            _, reason = self.queue._current(c, row, now)
            if reason:
                return self.queue._public(self.queue._move(c, row, 'blocked', reason, now, worker))
            run = c.execute('SELECT id FROM tool_runs WHERE job_id=? AND attempt=?', (row['id'], row['attempts'])).fetchone()
            item = c.execute('SELECT * FROM tool_inputs WHERE job_id=?', (row['id'],)).fetchone()
            c.execute("SAVEPOINT tool_publish")
            try:
                require(item is not None and digest(item['document_json'].encode()) == item['input_sha'], 'Tool input integrity failure')
                payload = json.loads(item['document_json'])
                validate_input(row['type'], row['target'], row['method'], payload)
                output = interpret(plan(row['type'], row['target'], row['method']), payload)
                output.update(job_id=row['id'], run_id=run['id'], policy_revision=row['policy_revision'],
                              input_sha=item['input_sha'], artifact_refs=[])
                if payload['capture'] is not None:
                    for stream in ('stdout', 'stderr'):
                        content = decode(payload['capture'][stream+'_base64'])
                        sha = digest(content)
                        existing = c.execute('SELECT content,size FROM artifacts WHERE sha256=?', (sha,)).fetchone()
                        require(existing is None or (existing['content'] == content and existing['size'] == len(content)), 'Artifact integrity failure')
                        c.execute('INSERT OR IGNORE INTO artifacts VALUES (?,?,?)', (sha, content, len(content)))
                        c.execute('INSERT INTO tool_artifacts VALUES (?,?,?)', (run['id'], stream, sha))
                        output['artifact_refs'].append({'stream': stream, 'sha256': sha, 'size': len(content), 'origin': 'supplied_capture_unverified'})
                error = output['error']
            except (ToolError, ValueError, TypeError, KeyError):
                c.execute("ROLLBACK TO tool_publish")
                output = {'job_id': row['id'], 'run_id': run['id'], 'executed': False, 'error': 'invalid_tool_input_or_artifact'}
                error = output['error']
            c.execute("RELEASE tool_publish")
            document = canonical(output)
            status = 'failed' if error else 'succeeded'
            reason = error or 'dry_run_tool_completed'
            updated = self.queue._move(c, row, status, reason, now, worker, result_json=document)
            c.execute('UPDATE tool_runs SET output_json=?,output_sha=? WHERE id=?', (document, digest(document.encode()), run['id']))
            return self.queue._public(updated)

    def runs(self, job_id=None):
        with self.database.transaction() as c:
            return [dict(row) for row in c.execute('SELECT id,job_id,attempt,status,reason,started_at,ended_at,output_sha FROM tool_runs WHERE (? IS NULL OR job_id=?) ORDER BY started_at,id', (job_id, job_id))]

    def show_run(self, run_id):
        with self.database.transaction() as c:
            row = c.execute('SELECT * FROM tool_runs WHERE id=?', (run_id,)).fetchone()
            require(row is not None, 'Unknown tool run')
            result = dict(row)
            document = result.pop('output_json')
            require(document is None or digest(document.encode()) == row['output_sha'], 'Tool result integrity failure')
            result['output'] = json.loads(document) if document else None
            return result

    def export(self, run_id, stream, destination):
        require(stream in {'stdout', 'stderr'}, 'Invalid artifact stream')
        run = self.show_run(run_id)
        refs = (run['output'] or {}).get('artifact_refs', [])
        reference = next((ref for ref in refs if ref['stream'] == stream), None)
        require(reference is not None, 'Capture artifact unavailable')
        with self.database.transaction() as c:
            row = c.execute('SELECT a.* FROM artifacts a JOIN tool_artifacts t ON a.sha256=t.sha256 WHERE t.run_id=? AND t.stream=?', (run_id, stream)).fetchone()
            require(row is not None and row['sha256'] == reference['sha256'] == digest(row['content']) and row['size'] == reference['size'] == len(row['content']), 'Tool artifact integrity failure')
            content = row['content']
        with Path(destination).open('xb') as output:
            output.write(content)
        return reference
