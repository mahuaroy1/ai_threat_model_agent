"""End-to-end demo: scan an example app and add a narrative from a local Qwen model in Ollama.

Prerequisites::

    ollama pull qwen2.5-coder:7b
    ollama serve            # if Ollama is not already running

Run from the repository root (no installation needed)::

    python examples/run_demo.py
    python examples/run_demo.py --target examples/secure_support_agent --model qwen2.5:7b

Reports are written to ``examples/output/<target name>/``. If Ollama is not
reachable, the demo still writes the static threat model and explains why the
narrative is missing.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

EXAMPLES_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(EXAMPLES_DIR.parent / "src"))  # allow running without `pip install`

from ai_threat_model.engine import build_threat_model  # noqa: E402
from ai_threat_model.errors import LLMError, ThreatModelError  # noqa: E402
from ai_threat_model.logging_setup import configure_logging  # noqa: E402
from ai_threat_model.narrative import generate_narrative  # noqa: E402
from ai_threat_model.ollama_client import (  # noqa: E402
    DEFAULT_OLLAMA_MODEL,
    DEFAULT_OLLAMA_URL,
    DEFAULT_TIMEOUT_SECONDS,
    OllamaClient,
)
from ai_threat_model.reporting import write_reports  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--target", type=Path, default=EXAMPLES_DIR / "vulnerable_support_agent")
    parser.add_argument("--model", default=DEFAULT_OLLAMA_MODEL)
    parser.add_argument("--url", default=DEFAULT_OLLAMA_URL)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_SECONDS,
                        help="max seconds without output from Ollama (prompt processing or between tokens)")
    parser.add_argument("--retries", type=int, default=2, help="retries after transient Ollama failures")
    args = parser.parse_args()

    configure_logging("INFO")
    try:
        client = OllamaClient(base_url=args.url, model=args.model,
                              timeout_seconds=args.timeout, max_retries=args.retries)
        print(f"Scanning {args.target} ...")
        model = build_threat_model(args.target)
        print(f"Found {len(model.components)} components and {len(model.findings)} findings.")

        print(f"Asking {args.model} at {client.base_url} for a narrative (this can take a minute) ...")
        try:
            generate_narrative(model, client)
            print("\n----- AI narrative (advisory) -----\n")
            print(model.llm_narrative)
            print("\n-----------------------------------\n")
        except LLMError as error:
            print(f"Narrative skipped: {error}")
            model.errors.append(f"AI narrative skipped: {error}")

        output_dir = EXAMPLES_DIR / "output" / args.target.resolve().name
        for path in write_reports(model, output_dir, ["md", "json", "sarif"]):
            print(f"Report: {path}")
    except ThreatModelError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
