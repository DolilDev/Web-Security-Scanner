from __future__ import annotations

from asyncio import Semaphore, gather
from typing import Iterable

from .base import ScanContext, SecurityTest, TestResult


class TestRegistry:
    def __init__(self) -> None:
        self._tests: list[SecurityTest] = []

    def register(self, test: SecurityTest) -> None:
        self._tests.append(test)

    @property
    def tests(self) -> list[SecurityTest]:
        return list(self._tests)


registry = TestRegistry()


async def run_tests(target: ScanContext, concurrency: int = 10) -> list[TestResult]:
    semaphore = Semaphore(concurrency)

    async def _run(test: SecurityTest) -> TestResult:
        async with semaphore:
            return await test.run(target)

    return await gather(*(_run(test) for test in registry.tests))
