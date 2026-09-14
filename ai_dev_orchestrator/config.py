"""Strict TOML configuration parsing. Commands are data and are never executed."""
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath
import re
import tomllib

from .policy import BUILTIN_STOP_CODES, MAX_AUTO_FIX_ROUNDS

PROTECTED_PATHS = (
    "AGENTS.md", "docs/PROJECT_CHARTER.md", "docs/PRD.md",
    "docs/ENGINEERING_DESIGN.md", ".github/workflows/**",
    ".ai-orchestrator.toml", ".gitattributes", ".gitmodules",
)


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class SITCommand:
    id: str
    command: str
    shell: str
    working_directory: str
    timeout_seconds: int
    required: bool
    artifacts: tuple[str, ...]


@dataclass(frozen=True)
class Config:
    schema_version: int
    project_name: str
    repository: str
    max_auto_fix_rounds: int
    protected_paths: tuple[str, ...]
    agent_os: str
    sit_os: tuple[str, ...]
    review_required: bool
    review_independent: bool
    review_read_only: bool
    blocking_severities: tuple[str, ...]
    stop_extensions: tuple[str, ...]
    commands: tuple[SITCommand, ...]

    @property
    def stop_codes(self) -> frozenset[str]:
        return BUILTIN_STOP_CODES | frozenset(self.stop_extensions)


def _table(value, allowed, required=()):
    if type(value) is not dict:
        raise ConfigError("expected TOML table")
    if set(value) - set(allowed) or set(required) - set(value):
        raise ConfigError("unknown key or missing required key")
    return value


def _string(value):
    if type(value) is not str or not value.strip():
        raise ConfigError("expected nonempty string")
    return value


def _integer(value, low, high=None):
    if type(value) is not int or value < low or (high is not None and value > high):
        raise ConfigError("integer outside allowed bounds")
    return value


def _boolean(value):
    if type(value) is not bool:
        raise ConfigError("expected boolean")
    return value


def _strings(value):
    if type(value) is not list:
        raise ConfigError("expected string array")
    result = tuple(_string(v) for v in value)
    if len(set(result)) != len(result):
        raise ConfigError("duplicate array entry")
    return result


def _relative(value, *, glob=False, root=None):
    value = _string(value)
    windows = PureWindowsPath(value)
    if (windows.drive or windows.root or value.startswith(("/", "~"))
            or "\\" in value or ":" in value
            or any(ord(c) < 32 for c in value)
            or any(p in ("..", "") for p in value.split("/"))
            or (not glob and any(c in value for c in "*?[]"))):
        raise ConfigError("unsafe relative path")
    if root is not None:
        # Validate existing path and fixed glob prefix against symlink escape.
        prefix = value
        if glob:
            parts = []
            for part in value.split("/"):
                if any(c in part for c in "*?[]"):
                    break
                parts.append(part)
            prefix = "/".join(parts) or "."
        resolved_root = Path(root).resolve()
        try:
            (resolved_root / prefix).resolve().relative_to(resolved_root)
        except (ValueError, OSError, RuntimeError) as exc:
            raise ConfigError("path escapes project root") from exc
    return value


def parse_config(source: str, *, project_root=None, expected_repository=None) -> Config:
    """No commands/network. Optional root checks existing symlink prefixes only.

    A future executor must repeat path checks at use time; parsing is not a
    filesystem sandbox and cannot prevent later mutations or glob symlinks.
    """
    try:
        raw = tomllib.loads(source)
    except (tomllib.TOMLDecodeError, TypeError) as exc:
        raise ConfigError("invalid TOML") from exc
    return validate_config(raw, project_root=project_root, expected_repository=expected_repository)


def load_config(path, *, expected_repository=None) -> Config:
    """Load local TOML; callers enforcing authorization must supply the target.

    None is only for offline/syntax inspection, not an authorization decision.
    """
    path = Path(path)
    return parse_config(path.read_text(encoding="utf-8"), project_root=path.parent,
                        expected_repository=expected_repository)


def validate_config(raw: dict, *, project_root=None, expected_repository=None) -> Config:
    raw = _table(raw, ("schema_version", "project", "policy", "platform", "review", "stop", "sit"),
                 ("schema_version", "project", "platform", "review", "sit"))
    version = _integer(raw["schema_version"], 1, 1)
    project = _table(raw["project"], ("name", "repository"), ("name", "repository"))
    name = _string(project["name"])
    repository = _string(project["repository"])
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*", repository):
        raise ConfigError("invalid owner/repository")
    if expected_repository is not None and repository != expected_repository:
        raise ConfigError("repository is not the authorized target")
    policy = _table(raw.get("policy", {}), ("max_auto_fix_rounds", "protected_paths"))
    budget = _integer(policy.get("max_auto_fix_rounds", MAX_AUTO_FIX_ROUNDS), 0, 3)
    protected = _strings(policy.get("protected_paths", list(PROTECTED_PATHS)))
    if not set(PROTECTED_PATHS).issubset(protected):
        raise ConfigError("protected path weakening")
    for item in protected:
        _relative(item, glob=True)
    platform = _table(raw["platform"], ("agent_os", "sit_os"), ("agent_os", "sit_os"))
    agent_os = _string(platform["agent_os"])
    sit_os = _strings(platform["sit_os"])
    if agent_os != "linux" or not sit_os or set(sit_os) - {"linux", "windows"}:
        raise ConfigError("invalid platform policy")
    review = _table(raw["review"], ("required", "independent", "read_only", "blocking_severities"),
                    ("required", "independent", "read_only", "blocking_severities"))
    flags = tuple(_boolean(review[k]) for k in ("required", "independent", "read_only"))
    severities = _strings(review["blocking_severities"])
    if not all(flags) or set(severities) != {"P0", "P1"}:
        raise ConfigError("review policy must require independent read-only P0/P1 gate; P2 is nonblocking")
    stop = _table(raw.get("stop", {}), ("extensions",))
    extensions = _strings(stop.get("extensions", []))
    if any(not re.fullmatch(r"[A-Z][A-Z0-9_]*", x) for x in extensions):
        raise ConfigError("stop extension must be a declarative code")
    sit = _table(raw["sit"], ("commands",), ("commands",))
    if type(sit["commands"]) is not list:
        raise ConfigError("commands must be array")
    commands = []
    for item in sit["commands"]:
        item = _table(item, ("id", "command", "shell", "working_directory",
                            "timeout_seconds", "required", "artifacts"),
                      ("id", "command", "shell", "timeout_seconds"))
        identity, command, shell = (_string(item[k]) for k in ("id", "command", "shell"))
        if shell not in ("bash", "pwsh"):
            raise ConfigError("invalid shell")
        cwd = _relative(item.get("working_directory", "."), root=project_root)
        timeout = _integer(item["timeout_seconds"], 1)
        required = _boolean(item.get("required", True))
        artifacts = _strings(item.get("artifacts", []))
        for path in artifacts:
            _relative(path, glob=True, root=project_root)
            lower = path.lower()
            if (path in (".", "*", "**", "**/*") or
                    any(p == ".git" or p.startswith(".env") or p in (".ssh", ".aws", ".config")
                        for p in lower.split("/")) or lower.endswith((".pem", ".key"))):
                raise ConfigError("unsafe artifact policy")
        commands.append(SITCommand(identity, command, shell, cwd, timeout, required, artifacts))
    if len({c.id for c in commands}) != len(commands):
        raise ConfigError("duplicate SIT id")
    if not any(c.required for c in commands):
        raise ConfigError("empty required SIT set")
    return Config(version, name, repository, budget, protected, agent_os, sit_os,
                  *flags, severities, extensions, tuple(commands))
