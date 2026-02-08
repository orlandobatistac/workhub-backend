"""Simple wrapper to run bandit and decide failure by severity.

Produces JSON report at `reports/bandit.json`. Exits with code 1 if any issue
matches severities in BANDIT_FAIL_SEVERITIES (comma-separated list, default=HIGH).
"""
from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
from typing import List

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

REPORT_DIR = os.path.abspath(os.path.join(os.getcwd(), "reports"))
os.makedirs(REPORT_DIR, exist_ok=True)
REPORT_PATH = os.path.join(REPORT_DIR, "bandit.json")

FAIL_SEVERITIES = os.getenv("BANDIT_FAIL_SEVERITIES", "HIGH")
FAIL_SEVERITIES = [s.strip().upper() for s in FAIL_SEVERITIES.split(",") if s.strip()]


def run_bandit() -> int:
    cmd = [sys.executable, "-m", "bandit", "-r", ".", "-x", "tests", "-f", "json", "-o", REPORT_PATH]
    logger.info("Running Bandit: %s", " ".join(cmd))
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode not in (0, 1):
        logger.error("Bandit failed to run: %s", res.stderr)
        return 2
    logger.info("Bandit finished, report at %s", REPORT_PATH)
    return res.returncode


def parse_report(path: str) -> List[dict]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
            return data.get("results", [])
    except Exception as exc:
        logger.error("Failed to read bandit report: %s", exc)
        return []


def summarize(results: List[dict]) -> int:
    matched = []
    for issue in results:
        sev = (issue.get("issue_severity") or "").upper()
        if sev in FAIL_SEVERITIES:
            matched.append(issue)
    if matched:
        logger.error("Found %d Bandit issue(s) with severities %s", len(matched), ",".join(FAIL_SEVERITIES))
        for i in matched:
            logger.error("%s:%s %s - %s", i.get("filename"), i.get("line_number"), i.get("issue_severity"), i.get("issue_text"))
        return 1
    logger.info("No Bandit issues matched severities: %s", ",".join(FAIL_SEVERITIES))
    return 0


def main() -> int:
    rc = run_bandit()
    if rc == 2:
        return 2
    results = parse_report(REPORT_PATH)
    return summarize(results)


if __name__ == "__main__":
    sys.exit(main())
