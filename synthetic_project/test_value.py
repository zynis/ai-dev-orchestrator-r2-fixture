"""Deterministic SIT intentionally accepts 1; mock review detects spec value != 2."""
from pathlib import Path
value = int(Path("synthetic_project/value.txt").read_text().strip())
assert value in (1, 2)
print("SIT positive control PASS")
