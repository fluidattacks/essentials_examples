#!/usr/bin/env python3
"""
Compare SAST SARIF findings against the CI agent (forces) JSON report.

Modes:
  strict  Compare by (path, line). Fails if SAST finds a location not already
          tracked in the platform. Default mode.
  lax     Compare by (category, path) counts. Category is the ruleId in SARIF
          and the first 3 characters of the finding title in the CI agent report.
          Fails if SAST has more findings for a (category, path) pair than the
          platform — meaning new occurrences appeared, even if the exact line
          differs.

CI agent report schema (forces JSON):
  findings[].title:                    "344. Lack of data validation - ..."
  findings[].vulnerabilities[]:
    technique:      "SAST" | "SCA" | ...
    where:          "<root_nickname>/<relative_path>"
    specific:       "<line_number>"   (string, strict mode only)
    root_nickname:  "<root_nickname>"

SARIF schema:
  runs[].results[]:
    ruleId:                            "344"
    locations[].physicalLocation:
      artifactLocation.uri:            "<relative_path>"   (no root_nickname prefix)
      region.startLine:                <line_number>       (int, strict mode only)
"""

import argparse
import json
import os
import sys
from collections import Counter


def normalize_path(path: str) -> str:
    return path.lstrip("./")


def _strip_root(where: str, root_nickname: str) -> str:
    if root_nickname and where.startswith(root_nickname + "/"):
        return where[len(root_nickname) + 1 :]
    return where


# ── strict ────────────────────────────────────────────────────────────────────


def parse_sast_strict(sarif_path: str) -> set[tuple[str, int]]:
    if not os.path.exists(sarif_path):
        print(f"No SAST results file at {sarif_path} — assuming no findings.")
        return set()

    with open(sarif_path) as f:
        sarif = json.load(f)

    locations: set[tuple[str, int]] = set()
    for run in sarif.get("runs", []):
        for result in run.get("results", []):
            for loc in result.get("locations", []):
                phys = loc.get("physicalLocation", {})
                uri = phys.get("artifactLocation", {}).get("uri", "")
                line = phys.get("region", {}).get("startLine", 0)
                if uri:
                    locations.add((normalize_path(uri), int(line)))
    return locations


def parse_ci_agent_strict(report_path: str) -> set[tuple[str, int]] | None:
    if not os.path.exists(report_path):
        print(f"No CI agent report at {report_path}.")
        return None

    with open(report_path) as f:
        report = json.load(f)

    locations: set[tuple[str, int]] = set()
    for finding in report.get("findings", []):
        for vuln in finding.get("vulnerabilities", []):
            if vuln.get("technique") != "SAST":
                continue
            where = _strip_root(vuln.get("where", ""), vuln.get("root_nickname", ""))
            try:
                line = int(vuln.get("specific", "0"))
            except ValueError:
                continue
            if where:
                locations.add((normalize_path(where), line))
    return locations


def run_strict(sarif_path: str, report_path: str) -> None:
    sast = parse_sast_strict(sarif_path)
    ci_agent = parse_ci_agent_strict(report_path)

    print(f"SAST findings:               {len(sast)}")

    if ci_agent is None:
        print(
            "CI agent report is missing — cannot determine new vs. existing vulnerabilities."
        )
        sys.exit(1)

    print(f"Platform-tracked SAST vulns: {len(ci_agent)}")

    new_vulns = sast - ci_agent
    if new_vulns:
        print(f"\nNew vulnerabilities not tracked in the platform ({len(new_vulns)}):")
        for path, line in sorted(new_vulns):
            print(f"  {path}:{line}")
        sys.exit(1)

    print("\nAll SAST findings are already tracked in the platform.")


# ── lax ───────────────────────────────────────────────────────────────────────


def parse_sast_lax(sarif_path: str) -> Counter:
    if not os.path.exists(sarif_path):
        print(f"No SAST results file at {sarif_path} — assuming no findings.")
        return Counter()

    with open(sarif_path) as f:
        sarif = json.load(f)

    counter: Counter = Counter()
    for run in sarif.get("runs", []):
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "")
            for loc in result.get("locations", []):
                phys = loc.get("physicalLocation", {})
                uri = phys.get("artifactLocation", {}).get("uri", "")
                if uri:
                    counter[(rule_id, normalize_path(uri))] += 1
    return counter


def parse_ci_agent_lax(report_path: str) -> Counter | None:
    if not os.path.exists(report_path):
        print(f"No CI agent report at {report_path}.")
        return None

    with open(report_path) as f:
        report = json.load(f)

    counter: Counter = Counter()
    for finding in report.get("findings", []):
        category = finding.get("title", "")[:3]
        for vuln in finding.get("vulnerabilities", []):
            if vuln.get("technique") != "SAST":
                continue
            where = _strip_root(vuln.get("where", ""), vuln.get("root_nickname", ""))
            if where:
                counter[(category, normalize_path(where))] += 1
    return counter


def run_lax(sarif_path: str, report_path: str) -> None:
    sast = parse_sast_lax(sarif_path)
    ci_agent = parse_ci_agent_lax(report_path)

    print(f"SAST findings:               {sum(sast.values())}")

    if ci_agent is None:
        print(
            "CI agent report is missing — cannot determine new vs. existing vulnerabilities."
        )
        sys.exit(1)

    print(f"Platform-tracked SAST vulns: {sum(ci_agent.values())}")

    failures = [
        (cat, path, sast_n, ci_agent.get((cat, path), 0))
        for (cat, path), sast_n in sorted(sast.items())
        if sast_n > ci_agent.get((cat, path), 0)
    ]

    if failures:
        print(
            f"\nNew vulnerabilities not tracked in the platform ({len(failures)} group(s)):"
        )
        for category, path, sast_n, ci_n in failures:
            print(f"  [{category}] {path}  (SAST: {sast_n}, platform: {ci_n})")
        sys.exit(1)

    print("\nAll SAST findings are already tracked in the platform.")


# ── entry point ───────────────────────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Compare SAST findings against the CI agent platform report."
    )
    parser.add_argument(
        "--mode",
        choices=["strict", "lax"],
        default="strict",
        help=(
            "strict: fail if any (path, line) in SAST is not in the platform (default); "
            "lax: fail if SAST has more findings for a (category, path) pair than the platform"
        ),
    )
    parser.add_argument("sarif", metavar="sast.sarif")
    parser.add_argument("report", metavar="ci-agent-report.json")
    args = parser.parse_args()

    if args.mode == "strict":
        run_strict(args.sarif, args.report)
    else:
        run_lax(args.sarif, args.report)


if __name__ == "__main__":
    main()
