"""Tests for the fuzzing engine in :mod:`vulnforge.fuzz.engine`."""
from __future__ import annotations

from vulnforge.fuzz import FuzzEngine, mutate
from vulnforge.fuzz.crash import Crash


class TestMutate:
    def test_returns_bytes(self):
        out = mutate(b"hello world")
        assert isinstance(out, bytes)

    def test_deterministic_with_seed(self):
        import random
        rng1 = random.Random(7)
        rng2 = random.Random(7)
        assert mutate(b"payload", rng1) == mutate(b"payload", rng2)


class TestFuzzEngine:
    def test_collects_crash(self):
        def target(data: bytes) -> None:
            if data != b"safe":
                raise ValueError("boom")

        engine = FuzzEngine({"fuzz": {"max_iterations": 100}})
        crashes = engine.fuzz(target, seeds=[b"safe"], iterations=100)

        assert len(crashes) >= 1
        assert all(isinstance(c, Crash) for c in crashes)
        assert crashes[0].exc_type == "ValueError"
        assert crashes[0].crash_type == "exception"
        assert crashes[0].iteration >= 0

    def test_no_crash_when_target_never_fails(self):
        def target(data: bytes) -> None:
            pass

        engine = FuzzEngine({"fuzz": {"max_iterations": 50}})
        crashes = engine.fuzz(target, seeds=[b"a", b"bb"], iterations=50)
        assert crashes == []

    def test_respects_iteration_cap(self):
        calls = {"n": 0}

        def target(data: bytes) -> None:
            calls["n"] += 1

        engine = FuzzEngine({"fuzz": {"max_iterations": 1000}})
        engine.fuzz(target, seeds=[b"seed"], iterations=25)
        assert calls["n"] == 25

    def test_crash_to_dict_roundtrip(self):
        crash = Crash(
            input_bytes=b"\x00\x01\xff",
            crash_type="out-of-bounds",
            exc_type="IndexError",
            message="list index out of range",
            iteration=3,
        )
        restored = Crash.from_dict(crash.to_dict())
        assert restored.input_bytes == crash.input_bytes
        assert restored.crash_type == "out-of-bounds"
        assert restored.exc_type == "IndexError"
        assert restored.iteration == 3
