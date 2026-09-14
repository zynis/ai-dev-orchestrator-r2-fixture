"""Thin trusted binding for the sole synthetic remote fixture."""
from dataclasses import replace
from ai_dev_orchestrator.r2_fixture import binding, FixtureAdapter

def load(root):
    return replace(binding(), config_source=(root / '.ai-orchestrator.toml').read_text()), FixtureAdapter()
