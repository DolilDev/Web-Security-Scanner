from __future__ import annotations

import json
import asyncio
from dataclasses import asdict
from typing import List

from ..base import ScanContext, TestResult
from ..registry import run_tests


async def run_scan(target: str, concurrency: int = 10) -> List[dict]:
    ctx = ScanContext(target)
    results = await run_tests(ctx, concurrency=concurrency)
    return [asdict(r) for r in results]


def save_report(report: List[dict], path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"results": report}, fh, indent=2)


def run_and_save(target: str, out: str | None = None, concurrency: int = 10) -> List[dict]:
    report = asyncio.run(run_scan(target, concurrency=concurrency))
    if out:
        save_report(report, out)
    return report


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Run Web Security Scanner tests against a target and optionally save JSON report")
    parser.add_argument("target")
    parser.add_argument("--out", "-o", help="Output JSON file path")
    parser.add_argument("--concurrency", "-c", type=int, default=10, help="Concurrency for test execution")
    args = parser.parse_args()
    run_and_save(args.target, out=args.out, concurrency=args.concurrency)
