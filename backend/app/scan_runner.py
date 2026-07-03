from backend.app.tests_engine.orchestration.runner import run_and_save


def main():
    import sys
    if len(sys.argv) < 2:
        print("Usage: python -m backend.app.scan_runner <target> [--out=report.json]")
        return
    target = sys.argv[1]
    out = None
    if len(sys.argv) > 2 and sys.argv[2].startswith("--out="):
        out = sys.argv[2].split("=", 1)[1]
    run_and_save(target, out=out)


if __name__ == "__main__":
    main()
