"""Local CLI for dry-run Kali adapters."""
import json
from pathlib import Path
from .data_cli import pairs
from .jobs import JobQueue
from .tool_adapters import OPERATIONS, ToolError
from .tool_runtime import ToolRuntime


def register(commands):
    commands = commands.add_parser('tools', help='Controlled dry-run Kali adapters').add_subparsers(dest='tool_command', required=True)
    commands.add_parser('list')
    enqueue = commands.add_parser('enqueue')
    enqueue.add_argument('action', choices=OPERATIONS)
    enqueue.add_argument('target')
    enqueue.add_argument('--program', required=True)
    enqueue.add_argument('--input', type=Path, help='Optional version 1 supplied-capture JSON')
    enqueue.add_argument('--key')
    worker = commands.add_parser('run-next')
    worker.add_argument('--worker', default='local-tool-worker')
    runs = commands.add_parser('runs')
    runs.add_argument('--job')
    show = commands.add_parser('run-show')
    show.add_argument('run_id')
    export = commands.add_parser('export')
    export.add_argument('run_id')
    export.add_argument('stream', choices=['stdout', 'stderr'])
    export.add_argument('destination', type=Path)


def dispatch(args, database):
    runtime = ToolRuntime(JobQueue(database))
    if args.tool_command == 'enqueue':
        payload = None
        if args.input:
            with args.input.open(encoding='utf-8-sig') as source:
                raw = source.read(180001)
            if len(raw) > 180000:
                raise ToolError('Tool input file too large')
            try:
                payload = json.loads(raw, object_pairs_hook=pairs)
            except (ValueError, RecursionError) as error:
                raise ToolError('Invalid tool input JSON') from error
            if payload is None:
                raise ToolError('Tool input must be an object')
        return runtime.enqueue(args.action, args.program, args.target, payload, key=args.key)
    if args.tool_command == 'run-next':
        return runtime.run_next(args.worker)
    if args.tool_command == 'list':
        result = {'operations': [{'action': name, 'method': method} for name, method in OPERATIONS.items()],
                  'mode': 'dry_run_only', 'kali_vm_verified': False}
    elif args.tool_command == 'runs':
        result = runtime.runs(args.job)
    elif args.tool_command == 'run-show':
        result = runtime.show_run(args.run_id)
    else:
        result = runtime.export(args.run_id, args.stream, args.destination)
    return {'ok': True, 'tools': result, 'execution_enabled': False}
