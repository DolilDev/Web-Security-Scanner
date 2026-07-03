from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any


@dataclass
class TestResult:
    id: str
    status: str
    evidence: str | None = None
    recommendation: str | None = None
    references: list[str] | None = None
    severity: str | None = None


class ScanContext:
    def __init__(self, target: str, metadata: dict[str, Any] | None = None) -> None:
        self.target = target
        self.metadata = metadata or {}


class SecurityTest(ABC):
    id: str
    category: str
    severity: str

    @abstractmethod
    async def run(self, target: ScanContext) -> TestResult:
        raise NotImplementedError
