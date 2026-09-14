"""Small immutable installation binding; business configuration remains R1 TOML."""
from dataclasses import dataclass
import re

from .config import parse_config
from .candidate_transport import hash_bytes


@dataclass(frozen=True)
class ProjectBinding:
    repository: str
    planner_login: str
    planner_id: str
    branch: str
    workflows: tuple[str, ...]
    branch_prefix: str
    config_source: str
    adapter_identity: str

    def __post_init__(self):
        parse_config(self.config_source, expected_repository=self.repository)
        for value in (self.branch, self.branch_prefix):
            if not re.fullmatch(r'[a-zA-Z0-9_/-]+', value):
                raise ValueError('invalid control/implementation branch binding')
        if not self.planner_login or not self.planner_id.isdecimal():
            raise ValueError('invalid actor binding')
        if not self.workflows or any(not re.fullmatch(r'\.github/workflows/[a-z0-9-]+\.yml', p) for p in self.workflows):
            raise ValueError('invalid workflow binding')

    @property
    def config(self):
        return parse_config(self.config_source, expected_repository=self.repository)

    @property
    def config_identity(self):
        return hash_bytes(self.config_source.encode())

    def implementation_branch(self, issue):
        if type(issue) is not int or issue < 1:
            raise ValueError('invalid Issue identity')
        return self.branch_prefix + str(issue)
