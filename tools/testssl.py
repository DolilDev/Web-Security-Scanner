from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any


class TestSSLTool:
    def __init__(self, executable: str = "testssl.sh") -> None:
        self.executable = executable

    def is_available(self) -> bool:
        return shutil.which(self.executable) is not None

    def scan(self, target: str, timeout: int = 60) -> dict[str, Any]:
        if not self.is_available():
            raise FileNotFoundError("testssl.sh executable was not found")

        with tempfile.NamedTemporaryFile("w+", suffix=".json", delete=False) as temp_file:
            output_path = Path(temp_file.name)

        cmd = [self.executable, "--jsonfile", str(output_path), target]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if result.returncode != 0 and not output_path.exists():
            raise RuntimeError(
                f"testssl.sh failed: {result.stderr.strip() or result.stdout.strip()}"
            )

        with output_path.open("r", encoding="utf-8") as file:
            data = json.load(file)
        output_path.unlink(missing_ok=True)
        return data


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python tools/testssl.py <target>")
        raise SystemExit(1)

    wrapper = TestSSLTool()
    try:
        data = wrapper.scan(sys.argv[1])
        print(json.dumps(data, indent=2))
    except Exception as exc:
        print(f"Error: {exc}")
        raise SystemExit(1)
