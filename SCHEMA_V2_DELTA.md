# APK Signal report schema 2.1

## Report structure

- Source file evidence includes the original filename, byte size, SHA-256, claimed extension, and a ledger reference.
- Analyzer metadata records the analyzer and Androguard versions, analyzer script hash, SDK attribution catalog version, analysis limits, and code-offset interpretation.
- `components[]` contains APK-level findings. An APKM report has one component per inner APK; a standalone APK has one component.
- `evidence_ledger[]` records package facts and static indicators with stable IDs derived from container SHA-256, locator, and raw-value SHA-256.
- `destinations[]` contains normalized URL, domain, IP, and WebSocket records. Each record includes raw evidence references, component occurrences, noise classification, indicators, code-reference state, and limitations.
- `hosts[]` aggregates destination count, static statuses, flags, and noise classification by normalized host.
- `static_traces[]` is empty because register-level source-to-sink tracing is not implemented.
- `runtime_evidence` starts with `status: "none_imported"` and an empty `entries` array. Imported runtime evidence remains separate from static findings.
- `coverage` and `triage_summary` report analysis counts, unmodeled areas, and evidence needed before drawing runtime conclusions.
- `functionality_summary` records a reusable, report-time estimate of likely feature areas and manifest workflow clues, with supporting static indicators, permission/API hints, destination counts, and explicit limits. Workflow ordering and runtime execution are not inferred.

## Evidence interpretation

- `package_fact` covers hashes, manifest declarations, method references, and other package facts.
- `static_indicator` covers destination literals, decoded constant strings, and code API markers.
- A destination is `referenced_by_code` when Androguard reports a method reference to its DEX string. The report records the DEX file, class, method signature, and available offset. This does not establish that the method executes, that it calls a network sink, or that it transmits data.
- Class-prefix attribution is a versioned catalog hint. It can identify an app package prefix or a catalogued SDK namespace; it does not prove code ownership.
- The analyzer tries whole-string hex, Base64, and reversal decoding. It does not guess keys or recover arbitrary runtime-built values.
- API markers and permissions are static indicators. They do not show sensitive data reaches a destination.
- Runtime observations may only come from a separately imported capture. A shared host match does not prove which process originated the request.

## Compatibility and validation

- Flat component `network_indicators` and `endpoint_analysis` remain available for existing viewer filters.
- The viewer accepts report schemas 2.0 and 2.1. The command-line validator checks the JSON Schema, ledger IDs and raw-value hashes, evidence references, runtime-tier links, and orphan entries.
- The viewer can locally import HAR and mitmproxy JSON request metadata. It records header names and query/body key names but not header values or request bodies. This import is examiner-supplied and is not independently authenticated.
- RDAP enrichment requires a session opt-in. Queries are external enrichment and are logged separately from package evidence.

## Analysis limits

The analyzer does not execute the app, generate network traffic, capture DNS or requests, or perform register-level/interprocedural source-to-sink tracing. It does not establish what sensitive data was sent or where an actual request went. It does not follow call-graph reachability, callbacks, reflection, JNI, native code, or dynamically loaded code. Runtime-built, encrypted, and obfuscated values may be missed. Archive limits and coverage counts are included to make partial analysis visible.
