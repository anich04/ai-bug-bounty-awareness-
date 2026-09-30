"""Provider-independent model request contracts, offline response ingestion and usage."""
from dataclasses import dataclass
import json
import os
from pathlib import Path
from urllib.parse import urlsplit
from .data import canonical, digest, require, text
from .data_cli import pairs
from .integrations import IntegrationStore

PROVIDERS = {'openai': ('responses', 'OPENAI_API_KEY'), 'claude': ('messages', 'ANTHROPIC_API_KEY'), 'kimi': ('chat_completions', 'KIMI_API_KEY')}
TASKS = {'classification', 'analysis', 'large_context', 'validation', 'reporting'}


@dataclass(frozen=True)
class ProviderConfig:
    provider: str
    enabled: bool = False
    model: str = ''
    endpoint: str = ''
    max_output_tokens: int = 1024

    def validate(self):
        require(self.provider in PROVIDERS and type(self.enabled) is bool, 'Invalid provider configuration')
        require(type(self.max_output_tokens) is int and 1 <= self.max_output_tokens <= 32768, 'Invalid output token limit')
        if self.enabled:
            text(self.model, 200)
            parsed = urlsplit(self.endpoint)
            require(parsed.scheme == 'https' and parsed.hostname and not parsed.username and not parsed.password and not parsed.query and not parsed.fragment, 'Provider endpoint must be a credential-free HTTPS URL')
        return self


class ModelRouter:
    def __init__(self, configs=None, routes=None):
        self.configs = configs or {name: ProviderConfig(name) for name in PROVIDERS}
        self.routes = routes or {}
        require(set(self.configs) <= set(PROVIDERS) and all(k == v.provider for k,v in self.configs.items()), 'Provider configuration keys do not match')
        for config in self.configs.values(): config.validate()
        require(set(self.routes) <= TASKS and all(v in self.configs for v in self.routes.values()), 'Invalid model route')

    @classmethod
    def load(cls, path):
        if not path.exists(): return cls()
        require(path.stat().st_size <= 65536, 'Model configuration too large')
        try:
            value = json.loads(path.read_text(encoding='utf-8-sig'), object_pairs_hook=pairs)
            require(set(value) == {'providers','routes'}, 'Invalid model configuration fields')
            configs = {name: ProviderConfig(provider=name, **options) for name,options in value['providers'].items()}
            return cls(configs, value['routes'])
        except (TypeError, ValueError, AttributeError, KeyError) as error:
            from .data import DataError
            raise DataError('Invalid model configuration') from error

    def health(self):
        return [{'provider': name, 'enabled': config.enabled, 'model': config.model,
                 'credential_present': bool(os.environ.get(PROVIDERS[name][1])),
                 'api_verified': False, 'mode': 'offline_contracts_only'} for name,config in self.configs.items()]

    def select(self, task):
        require(task in TASKS, 'Unknown model task')
        name = self.routes.get(task)
        require(name in self.configs and self.configs[name].enabled, 'No enabled provider for this task')
        return self.configs[name]

    def request(self, task, prompt):
        config = self.select(task)
        text(prompt, 64000)
        if config.provider == 'openai':
            body = {'model': config.model, 'input': prompt, 'max_output_tokens': config.max_output_tokens, 'store': False}
        else:
            body = {'model': config.model, 'messages': [{'role': 'user', 'content': prompt}], 'max_tokens': config.max_output_tokens}
        return {'provider': config.provider, 'protocol': PROVIDERS[config.provider][0], 'endpoint': config.endpoint,
                'body': body, 'execution_enabled': False, 'credential_env': PROVIDERS[config.provider][1]}


def parse_response(provider, raw):
    require(provider in PROVIDERS and isinstance(raw, bytes) and len(raw) <= 1024*1024, 'Invalid provider response')
    try:
        value = json.loads(raw, object_pairs_hook=pairs)
        require(isinstance(value, dict) and not value.get('error'), 'Provider returned an error')
        if provider == 'openai':
            require(value.get('status') == 'completed', 'Model response is incomplete')
            parts = [part['text'] for item in value['output'] if item.get('type') == 'message' for part in item['content'] if part.get('type') == 'output_text']
            require(all(item.get('type') in {'message','reasoning'} for item in value['output']), 'Tool calls are not supported')
        elif provider == 'claude':
            require(value.get('stop_reason') == 'end_turn', 'Model response is incomplete or requests a tool')
            require(all(item.get('type') in {'text','thinking','redacted_thinking'} for item in value['content']), 'Unsupported response content')
            parts = [item['text'] for item in value['content'] if item.get('type') == 'text']
        else:
            choices = value['choices']; require(len(choices) == 1 and choices[0].get('finish_reason') == 'stop', 'Model response is incomplete')
            message = choices[0]['message']; require(not message.get('tool_calls'), 'Tool calls are not supported')
            parts = [message['content']]
        require(all(isinstance(part, str) for part in parts), 'Invalid generated text')
        answer = ''.join(parts); text(answer, 128000)
        usage = value.get('usage') or {}
        a,b = ('prompt_tokens','completion_tokens') if provider == 'kimi' else ('input_tokens','output_tokens')
        normalized = {'input_tokens': usage.get(a), 'output_tokens': usage.get(b)}
        require(all(x is None or (type(x) is int and 0 <= x <= 100000000) for x in normalized.values()), 'Invalid token usage')
        return {'text': answer, 'usage': normalized, 'cost_usd': None, 'origin': 'generated_unverified', 'provider_model': value.get('model')}
    except (ValueError, TypeError, KeyError, AttributeError, IndexError) as error:
        from .data import DataError
        raise DataError('Provider response is invalid, incomplete or unsupported') from error


def register(commands):
    subs = commands.add_parser('models', help='Offline model contracts and response ingestion').add_subparsers(dest='model_command', required=True)
    health = subs.add_parser('health'); health.add_argument('--config', type=Path)
    ingest = subs.add_parser('ingest'); ingest.add_argument('provider', choices=PROVIDERS); ingest.add_argument('file', type=Path); ingest.add_argument('--program', required=True); ingest.add_argument('--task', choices=sorted(TASKS), required=True)
    usage = subs.add_parser('usage'); usage.add_argument('--program')


def dispatch(args, database):
    if args.model_command == 'health':
        result = ModelRouter.load(args.config or args.root/'configs/models.json').health()
    elif args.model_command == 'usage':
        result = [{'id': r['id'], **r['payload']} for r in IntegrationStore(database).list(args.program, 'model_response')]
    else:
        with args.file.open('rb') as source: raw = source.read(1024*1024+1)
        response = parse_response(args.provider, raw)
        result = IntegrationStore(database).save(args.program, 'model_response',
                 {'provider': args.provider, 'task': args.task, 'response': response, 'latency_ms': None, 'network_call_made': False},
                 {'provider-response.json': raw}, targets=[])
    return {'ok': True, 'models': result, 'execution_enabled': False}
