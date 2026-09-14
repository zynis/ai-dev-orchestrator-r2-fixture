"""Finite offline effect driver with programmable mocks, not a daemon or CLI."""
from dataclasses import dataclass
from typing import Protocol

from .domain import (
    BoundResult, Delivery, EffectKind, Event, EventKind, Finding, Outcome,
    ReviewAccess, ReviewResult, RunState, Severity, State, TransitionResult,
)
from .state_machine import transition


class CandidateFixture(Protocol):
    @property
    def head(self) -> str: ...

    def commit_text(self, content: str) -> str: ...


class MockExecutor:
    def __init__(self, fixture: CandidateFixture):
        self.fixture = fixture
        self.calls = []

    def execute(self, state: RunState, attempt: int, required_fixes: tuple[Finding, ...]) -> Delivery:
        if self.fixture.head != state.current_sha:
            raise ValueError("local fixture head differs from current candidate")
        self.calls.append((attempt, tuple(f.id for f in required_fixes)))
        candidate = self.fixture.commit_text(f"candidate attempt={attempt}\n")
        return Delivery(state.run_id, state.round_id, attempt, state.base_sha,
                        state.current_sha, candidate, state.spec_digest, "mock-executor",
                        f"local-git:{candidate}")


class MockSIT:
    def __init__(self, outcomes=(Outcome.PASS,)):
        self.outcomes = tuple(outcomes)
        if not self.outcomes:
            raise ValueError("empty SIT program")
        self.calls = []

    def run(self, state):
        self.calls.append(state.current_sha)
        outcome = self.outcomes[min(state.auto_fix_count, len(self.outcomes) - 1)]
        return BoundResult(state.current_sha, state.spec_digest, outcome, "mock-sit")


@dataclass(frozen=True)
class ReviewProgram:
    outcome: Outcome = Outcome.PASS
    access: Outcome = Outcome.PASS
    findings: tuple[Finding, ...] = ()


class MockReviewer:
    def __init__(self, programs=(ReviewProgram(),)):
        self.programs = tuple(programs)
        if not self.programs:
            raise ValueError("empty review program")
        self.calls = []

    def run(self, state):
        self.calls.append(state.current_sha)
        program = self.programs[min(state.auto_fix_count, len(self.programs) - 1)]
        access = ReviewAccess(state.current_sha, state.spec_digest, program.access,
                              "mock-exact-diff", "mock-reviewer")
        counts = [sum(f.severity is s for f in program.findings) for s in Severity]
        review = ReviewResult(state.current_sha, state.spec_digest, program.outcome,
                              "mock-review", "mock-reviewer", True, *counts, program.findings)
        return access, review


@dataclass(frozen=True)
class SimulationTrace:
    state: RunState
    steps: tuple[TransitionResult, ...]
    step_limit_reached: bool


class SimulationRunner:
    def __init__(self, executor, sit, reviewer, step_limit=100):
        if type(step_limit) is not int or step_limit < 1:
            raise ValueError("positive step limit required")
        self.executor, self.sit, self.reviewer = executor, sit, reviewer
        self.step_limit = step_limit

    @staticmethod
    def event(state, kind, payload=None, *, authorized=False):
        return Event(f"simulation-{len(state.processed_event_ids)}", state.run_id, state.round_id,
                     kind, state.current_sha, state.spec_digest, state.auto_fix_count,
                     "offline-simulation", payload, authorized)

    def run(self, state: RunState, initial_event: Event | None = None) -> SimulationTrace:
        event = initial_event or self.event(state, EventKind.START, authorized=True)
        queue = [event]
        steps = []
        halt = (State.HUMAN_REVIEW_READY, State.HUMAN_DECISION_REQUIRED,
                State.BLOCKED, State.COMPLETED, State.CANCELLED)
        while queue and len(steps) < self.step_limit:
            event = queue.pop(0)
            result = transition(state, event)
            steps.append(result)
            state = result.new_state
            if result.disposition == "REJECTED":
                raise ValueError(result.errors)
            # A mock can return access + review together. Preserve already-known
            # P1/P0 even if the access half blocked; do not launch further work.
            pending_review = (state.state is State.BLOCKED and queue
                              and queue[0].kind is EventKind.REVIEW)
            if state.state in halt and not pending_review:
                return SimulationTrace(state, tuple(steps), False)
            for effect in result.effects:
                if effect.kind in (EffectKind.START_EXECUTOR, EffectKind.START_FIX):
                    delivery = self.executor.execute(state, effect.attempt, state.unresolved_findings)
                    queue.append(self.event(state, EventKind.DELIVERY, delivery))
                elif effect.kind is EffectKind.START_SIT:
                    queue.append(self.event(state, EventKind.SIT, self.sit.run(state)))
                elif effect.kind is EffectKind.START_REVIEW:
                    access, review = self.reviewer.run(state)
                    # Review data uses the same binding, but a distinct event ID.
                    access_event = self.event(state, EventKind.ACCESS, access)
                    review_event = Event(access_event.event_id + "-review", state.run_id, state.round_id,
                                         EventKind.REVIEW, state.current_sha, state.spec_digest,
                                         state.auto_fix_count, "offline-review", review)
                    queue.extend((access_event, review_event))
        return SimulationTrace(state, tuple(steps), bool(queue))
