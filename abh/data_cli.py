"""CLI boundary for local object imports and evidence exports."""
import json
from pathlib import Path
from .data import DataError, DataStore, MAX_ARTIFACT, PARENTS, require


def register(commands):
    commands = commands.add_parser('data', help='Import and inspect immutable local data and evidence').add_subparsers(dest='data_command', required=True)
    add = commands.add_parser('add')
    add.add_argument('kind', choices=PARENTS)
    add.add_argument('--program', required=True)
    add.add_argument('--parent')
    add.add_argument('--input', type=Path, required=True, help='JSON payload')
    add.add_argument('--artifact', type=Path, help='Original evidence file, at most 10 MiB')
    add.add_argument('--actor', default='local-human')
    listing = commands.add_parser('list')
    listing.add_argument('--program', required=True)
    listing.add_argument('--kind', choices=PARENTS)
    for command in ('show', 'provenance', 'export'):
        item = commands.add_parser(command)
        item.add_argument('object_id')
        if command == 'export':
            item.add_argument('destination', type=Path)


def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, 'Duplicate JSON key')
        result[key] = value
    return result


def dispatch(args, database):
    store = DataStore(database)
    if args.data_command == 'add':
        with args.input.open(encoding='utf-8-sig') as source:
            raw = source.read(131073)
        require(len(raw.encode()) <= 131072, 'Data payload too large')
        try:
            payload = json.loads(raw, object_pairs_hook=pairs)
        except (ValueError, RecursionError) as error:
            raise DataError('Invalid data JSON') from error
        content = None
        if args.artifact:
            with args.artifact.open('rb') as source:
                content = source.read(MAX_ARTIFACT + 1)
        result = store.create(args.kind, args.program, payload, parent_id=args.parent, actor=args.actor, content=content)
    elif args.data_command == 'list':
        result = store.list(args.program, args.kind)
    elif args.data_command == 'export':
        result = store.export(args.object_id, args.destination)
    else:
        result = getattr(store, args.data_command)(args.object_id)
    return {'ok': True, 'data': result, 'execution_enabled': False}
