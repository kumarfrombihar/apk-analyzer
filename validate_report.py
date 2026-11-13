#!/usr/bin/env python3
"""Validate an APK Signal v2 report and its evidence-ledger references."""
import argparse
import hashlib
import json
import re
import sys
from pathlib import Path


def fail(message):
    raise ValueError(message)


def validate_structural(report):
    required = ("schema_version", "package_format", "source_evidence", "analysis_metadata", "run", "evidence_ledger", "destinations", "static_traces", "coverage", "triage_summary", "analyst_notes", "components")
    for key in required:
        if key not in report:
            fail(f"Missing required root field: {key}")
    if report["schema_version"] not in {"2.0", "2.1"}:
        fail("Only APK Signal schema v2.0 and v2.1 reports are accepted.")
    if report["schema_version"] == "2.1":
        for key in ("hosts", "runtime_evidence"):
            if key not in report:
                fail(f"Schema v2.1 report is missing {key}")
    for key in ("evidence_ledger", "destinations", "static_traces", "components"):
        if not isinstance(report[key], list):
            fail(f"{key} must be an array")
    ids = []
    for item in report["evidence_ledger"]:
        for key in ("id", "tier", "container", "entry_path", "locator", "extraction_method", "decode_chain", "raw_value", "raw_value_sha256"):
            if key not in item:
                fail(f"Evidence ledger entry missing {key}")
        ids.append(item["id"])
        if item["tier"] not in {"package_fact", "static_indicator", "static_trace_step", "runtime_observation"}:
            fail(f"Invalid ledger tier: {item['tier']}")
        raw_hash = hashlib.sha256(item["raw_value"].encode("utf-8", errors="surrogatepass")).hexdigest()
        if raw_hash != item["raw_value_sha256"]:
            fail(f"Raw value hash mismatch for ledger entry {item['id']}")
        stable_material = json.dumps(
            {"container_sha256": item["container"]["sha256"], "locator": item["locator"], "raw_value_sha256": raw_hash},
            sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        )
        expected_id = hashlib.sha256(stable_material.encode("utf-8")).hexdigest()
        if expected_id != item["id"]:
            fail(f"Content-derived ledger ID mismatch for {item['id']}")
        if not re.fullmatch(r"[a-f0-9]{64}", item["container"]["sha256"]):
            fail(f"Invalid container SHA-256 on ledger entry {item['id']}")
    if len(ids) != len(set(ids)):
        fail("Duplicate evidence ledger IDs")
    for dest in report["destinations"]:
        for key in ("id", "kind", "normalized", "raw_evidence_ids", "occurrences", "observation_status", "unknowns", "indicators", "noise", "attribution"):
            if key not in dest:
                fail(f"Destination missing {key}")
    coverage = report["coverage"]
    if coverage.get("data_flow_analysis_status") not in {"performed", "partial", "not_performed"}:
        fail("Invalid coverage data_flow_analysis_status")
    return set(ids)


def validate_references(report, ledger_ids):
    references = set()

    def add(value, where):
        if not isinstance(value, str):
            fail(f"Non-string ledger reference at {where}")
        references.add(value)

    source_ref = report.get("source_evidence", {}).get("evidence_ledger_id")
    if source_ref:
        add(source_ref, "source_evidence")
    for reference in report.get("triage_summary", {}).get("evidence_ledger_ids", []):
        add(reference, "triage_summary")
    for highlight in report.get("triage_summary", {}).get("highlighted_destinations", []):
        for reference in highlight.get("evidence_ledger_ids", []):
            add(reference, "triage_summary.highlighted_destinations")
    for destination in report.get("destinations", []):
        for reference in destination.get("raw_evidence_ids", []):
            add(reference, "destination.raw_evidence_ids")
        for occurrence in destination.get("occurrences", []):
            add(occurrence.get("ledger_id"), "destination.occurrences")
    for component in report.get("components", []):
        for reference in component.get("evidence_ledger_ids", []):
            add(reference, "component.evidence_ledger_ids")
        if component.get("component_evidence_ledger_id"):
            add(component["component_evidence_ledger_id"], "component evidence")
        for indicator in component.get("behavior_analysis", {}).get("api_indicators", []):
            for reference in indicator.get("evidence_ledger_ids", []):
                add(reference, "behavior indicator")
    for trace in report.get("static_traces", []):
        for reference in trace.get("evidence_ledger_ids", []):
            add(reference, "static trace")
    for note in report.get("analyst_notes", []):
        for reference in note.get("evidence_ledger_ids", []):
            add(reference, "analyst note")
    runtime = report.get("runtime_evidence", {})
    for collection in (runtime.get("entries", []), runtime.get("requests", [])):
        for item in collection:
            reference = item.get("ledger_id") or item.get("evidence_ledger_id")
            if reference:
                add(reference, "runtime evidence")
    missing = references - ledger_ids
    if missing:
        fail("Unknown ledger references: " + ", ".join(sorted(missing)[:10]))
    orphaned = ledger_ids - references
    if orphaned:
        fail("Unreferenced evidence ledger entries: " + ", ".join(sorted(orphaned)[:10]))

    runtime_ids = {item["id"] for item in report["evidence_ledger"] if item["tier"] == "runtime_observation"}
    if runtime_ids and not (runtime.get("entries") or runtime.get("requests")):
        fail("runtime_observation ledger entries require imported runtime evidence entries")
    if not report.get("runtime_evidence") and report.get("analysis_metadata", {}).get("runtime_observed") is not False:
        fail("Static-only report must not claim runtime observations")


def validate_json_schema(report, schema_path):
    try:
        import jsonschema
    except ImportError:
        return "structural fallback (install jsonschema for full Draft 2020-12 validation)"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    validator = jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker())
    errors = sorted(validator.iter_errors(report), key=lambda error: list(error.path))
    if errors:
        first = errors[0]
        fail(f"JSON Schema validation failed at {list(first.path)}: {first.message}")
    return "JSON Schema 2020-12"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("reports", nargs="+", help="Report JSON files")
    parser.add_argument("--schema", default=str(Path(__file__).with_name("report.schema.json")))
    args = parser.parse_args()
    schema_path = Path(args.schema)
    failures = 0
    for filename in args.reports:
        try:
            report = json.loads(Path(filename).read_text(encoding="utf-8"))
            ledger_ids = validate_structural(report)
            validate_references(report, ledger_ids)
            mode = validate_json_schema(report, schema_path)
            print(f"VALID ({mode} + referential integrity): {filename}")
        except Exception as error:
            failures += 1
            print(f"INVALID: {filename}: {error}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
