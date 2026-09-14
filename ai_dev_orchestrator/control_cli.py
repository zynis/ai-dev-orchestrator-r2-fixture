"""Installed Actions entry point; fixed control-source binding."""
import argparse
import importlib.util
from pathlib import Path
from .github_runtime import GitHubRuntime


def main():
    root = Path(__file__).resolve().parents[1]
    module_spec = importlib.util.spec_from_file_location('trusted_project', root / 'control/project.py')
    module = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(module)
    binding, adapter = module.load(root)
    runtime = GitHubRuntime(binding, adapter)
    parser=argparse.ArgumentParser()
    parser.add_argument('phase', choices=('intake','enter','mock','publish','sit','review','gate','dispatch','recover','request-recovery'))
    phase=parser.parse_args().phase
    actions={'intake':runtime.intake,'enter':runtime.enter_attempt,'mock':adapter.mock_execute,
             'publish':runtime.publish,'sit':adapter.sit,'review':adapter.mock_review,'gate':runtime.gate,
             'dispatch':runtime.dispatcher,'recover':lambda:runtime.dispatcher(True),
             'request-recovery':runtime.request_recovery}
    actions[phase]()

if __name__ == '__main__':
    main()
