import argparse
import json
import sys
from pathlib import Path

from analyzer.core import MAX_LOG_BYTES, analyze


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Analyze a CI log locally. No log data is sent to AI."
    )
    parser.add_argument("log", type=Path)
    parser.add_argument("--json", action="store_true", help="Print a structured report")
    arguments = parser.parse_args()
    try:
        with arguments.log.open("rb") as source:
            data = source.read(MAX_LOG_BYTES + 1)
        if len(data) > MAX_LOG_BYTES:
            raise ValueError("The log exceeds the 5 MiB limit.")
        result = analyze(data.decode("utf-8-sig"))
    except (OSError, ValueError) as error:
        print(f"Cannot analyze log: {error}", file=sys.stderr)
        return 2
    if arguments.json:
        print(json.dumps(result, indent=2))
    else:
        for label in (
            "failure_type",
            "relevant_error",
            "likely_component",
            "suggested_investigation",
        ):
            print(
                f"{label.replace('_', ' ').title()}\n{'-' * len(label)}\n{result[label]}\n"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
