"""Human-reviewed local finding pipeline; never submits reports."""
from contextlib import contextmanager
from pathlib import Path
import json
from .data import DataStore, canonical, digest, require, text
from .integrations import IntegrationStore
from .programs import ProgramStore
from .scope import target_is_in_scope
from .data_cli import pairs

CHECKS = {'real','reproducible','in_scope','security_relevant','not_duplicate','evidence_sufficient'}
DECISIONS = {'validated','false_positive','duplicate','needs_evidence'}


class BoundDatabase:
    """Reuse the caller's write transaction for composed service operations."""
    def __init__(self, connection): self.connection = connection
    @contextmanager
    def transaction(self, *, write=False): yield self.connection


class FindingPipeline:
    def __init__(self, database): self.database = database

    def _state(self, c, finding_id):
        finding = DataStore._read(c, finding_id)
        require(finding['kind'] == 'finding', 'Expected a candidate finding')
        evidence = [DataStore._read(c, row['id']) for row in c.execute("SELECT id FROM data_objects WHERE parent_id=? AND kind='evidence' ORDER BY id", (finding_id,))]
        for item in evidence: DataStore._artifact(c, item)
        program = ProgramStore.read(c, finding['program_id'])
        snapshot = digest(canonical({'finding': finding, 'evidence': evidence, 'revision': program.revision}).encode())
        events = [IntegrationStore.read(c,row['id']) for row in c.execute("SELECT id FROM integration_records WHERE program_id=? AND kind='finding_review' ORDER BY rowid", (finding['program_id'],))]
        events = [event for event in events if event['payload']['finding_id'] == finding_id]
        latest = events[-1] if events else None
        scope = target_is_in_scope(program, finding['target']).allowed
        status = latest['payload']['decision'] if latest and latest['payload']['snapshot'] == snapshot and scope else 'needs_validation'
        return {'finding': finding, 'evidence': evidence, 'snapshot': snapshot, 'status': status,
                'in_scope': scope, 'reviews': events, 'submission_enabled': False}

    def show(self, finding_id):
        with self.database.transaction() as c: return self._state(c, finding_id)

    def duplicates(self, finding_id):
        with self.database.transaction() as c:
            source = self._state(c,finding_id)['finding']
            def key(item): return (item['target'], ' '.join(item['payload']['title'].lower().split()), ' '.join(item['payload']['hypothesis'].lower().split()))
            matches = []
            for row in c.execute("SELECT id FROM data_objects WHERE program_id=? AND kind='finding' AND id<>?", (source['program_id'],finding_id)):
                other = DataStore._read(c,row['id'])
                if key(source) == key(other): matches.append(other['id'])
            return {'candidate_matches': matches, 'method': 'exact_normalized_content', 'decision': 'human_review_required'}

    def review(self, finding_id, decision, checks, rationale, actor='local-human', duplicate_of=None):
        require(decision in DECISIONS, 'Invalid review decision')
        require(isinstance(checks,dict) and set(checks) == CHECKS and all(type(v) is bool for v in checks.values()), 'Review requires all six boolean checks')
        text(rationale); text(actor,100)
        with self.database.transaction(write=True) as c:
            state = self._state(c,finding_id); finding = state['finding']
            require(state['in_scope'], 'Finding is not currently authorized')
            if decision == 'validated':
                require(all(checks.values()), 'Validation requires all checks to pass')
                require(any(e['payload']['origin'] == 'raw_import' and e['payload']['size'] > 0 for e in state['evidence']), 'Validation requires nonempty raw evidence')
            if decision == 'duplicate':
                require(duplicate_of is not None and duplicate_of != finding_id, 'Duplicate review requires another finding')
                other = DataStore._read(c,duplicate_of)
                require(other['kind'] == 'finding' and other['program_id'] == finding['program_id'], 'Duplicate must belong to the same program')
            else: require(duplicate_of is None, 'Duplicate reference only applies to duplicate decisions')
            return IntegrationStore(BoundDatabase(c)).save(finding['program_id'],'finding_review',
                {'finding_id': finding_id, 'decision': decision, 'checks': checks, 'rationale': rationale,
                 'actor': actor, 'duplicate_of': duplicate_of, 'snapshot': state['snapshot'],
                 'authority': 'human_attestation', 'automatically_verified': False}, {}, targets=[finding['target']])

    def draft(self, finding_id, title, questions, actor='local-human'):
        with self.database.transaction(write=True) as c:
            state = self._state(c,finding_id)
            require(state['status'] == 'validated', 'A current human validation is required before preparing a report')
            report = DataStore(BoundDatabase(c)).create('report', state['finding']['program_id'],
                        {'title':title, 'questions':questions}, parent_id=finding_id, actor=actor)
            IntegrationStore(BoundDatabase(c)).save(report['program_id'],'report_workflow',
                {'report_id': report['id'], 'finding_id': finding_id, 'snapshot': state['snapshot'],
                 'decision': 'waiting_human', 'actor':actor}, {}, targets=[report['target']])
            return report

    def approve_report(self, report_id, actor='local-human'):
        text(actor,100)
        with self.database.transaction(write=True) as c:
            report = DataStore._read(c,report_id); require(report['kind']=='report','Expected a report')
            state = self._state(c,report['parent_id'])
            require(state['status']=='validated','Finding requires current validation')
            events = [IntegrationStore.read(c,row['id']) for row in c.execute("SELECT id FROM integration_records WHERE kind='report_workflow' AND program_id=? ORDER BY rowid",(report['program_id'],))]
            events = [e for e in events if e['payload']['report_id']==report_id]
            require(events and events[-1]['payload']['decision']=='waiting_human' and events[-1]['payload']['snapshot']==state['snapshot'], 'Report is not awaiting review against current evidence')
            for question in report['payload']['questions']:
                require(question['answer'] is not None and question['evidence_ids'], 'Every report answer requires text and evidence references')
                require(any(DataStore._read(c,eid)['payload']['origin']=='raw_import' for eid in question['evidence_ids']), 'Every report answer requires a raw evidence reference')
            return IntegrationStore(BoundDatabase(c)).save(report['program_id'],'report_workflow',
                {'report_id':report_id,'finding_id':report['parent_id'],'snapshot':state['snapshot'],
                 'decision':'approved','actor':actor,'submission_enabled':False}, {}, targets=[report['target']])


def register(commands):
    sub = commands.add_parser('findings',help='Review findings and prepare reports locally').add_subparsers(dest='finding_command',required=True)
    for action in ('show','duplicates','review','draft'):
        cmd=sub.add_parser(action);cmd.add_argument('finding_id')
        if action in {'review','draft'}: cmd.add_argument('--input',type=Path,required=True)
    approve=sub.add_parser('approve-report');approve.add_argument('report_id');approve.add_argument('--actor',default='local-human')


def dispatch(args,database):
    pipeline=FindingPipeline(database)
    if args.finding_command in {'show','duplicates'}: result=getattr(pipeline,args.finding_command)(args.finding_id)
    elif args.finding_command=='approve-report': result=pipeline.approve_report(args.report_id,args.actor)
    else:
        require(args.input.stat().st_size<=131072,'Finding input too large')
        try: value=json.loads(args.input.read_text(encoding='utf-8-sig'),object_pairs_hook=pairs)
        except (ValueError,RecursionError) as error:
            from .data import DataError
            raise DataError('Invalid finding input JSON') from error
        require(isinstance(value,dict),'Expected finding input object')
        if args.finding_command=='review':
            require(set(value)=={'decision','checks','rationale','actor','duplicate_of'},'Invalid review fields')
            result=pipeline.review(args.finding_id,**value)
        else:
            require(set(value)=={'title','questions','actor'},'Invalid draft fields')
            result=pipeline.draft(args.finding_id,**value)
    return {'ok':True,'finding':result,'execution_enabled':False}
