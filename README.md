# Project 01 - Syscall Pattern Profiler (Zig)

`sysprof` analyzes syscall/API trace lines and scores potential process injection and evasion behavior.

This is a recruiter-grade project for junior cybersecurity roles because it demonstrates:

- low-level Windows behavior understanding
- detection engineering mindset (signals + scoring)
- practical reporting for analysts

## Build

```powershell
zig build-exe .\sysprof.zig -target x86_64-windows-gnu -O ReleaseSmall -fstrip -femit-bin="sysprof.exe"
```

## Usage

```powershell
.\sysprof.exe .\sample_trace.txt --out profile_report.md
```

```powershell
.\sysprof.exe .\sample_trace.txt --baseline .\known_good_trace.txt --policy .\policy_default.json --profile auto --out profile_report.md --json profile_report.json
```

## Parser Profiles

`sysprof` supports multiple trace adapters via `--profile`:

- `auto` (default): try `kv`, then `edrjson`, then `csv`
- `kv`: key/value style lines (example: `pid=4120 syscall=NtWriteVirtualMemory`)
- `csv`: comma-separated rows (example in `sample_trace_csv.txt`)
- `edrjson`: one JSON object per line (example in `sample_trace_edrjson.txt`)

This makes it easier to plug into simple ETW/EDR export formats.

## Configurable Policy File

Use `--policy <file.json>` to override weights and thresholds.

Reference file: `policy_default.json`

Supported JSON keys:

- `weight_suspicious_call`
- `weight_direct_syscall`
- `weight_unhook`
- `weight_rwx`
- `weight_injection_chain`
- `weight_high_ratio`
- `threshold_ratio_min_calls`
- `threshold_ratio_pct`
- `baseline_weight_chain_delta`
- `baseline_ratio_increase_pct`
- `baseline_weight_ratio_delta`
- `baseline_multi_increase_min`
- `baseline_weight_multi_increase`
- `verdict_medium`
- `verdict_high`

## Expected trace format

`sysprof` is flexible and scans free-form lines, but best results come from lines containing fields like:

- `pid=1234`
- `syscall=NtAllocateVirtualMemory`
- optional metadata text (`rwx`, `hellsgate`, etc.)

Example line:

```text
time=12:00:01 pid=4120 syscall=NtAllocateVirtualMemory target=5560 protection=RWX
```

## Current scoring signals

- suspicious call families (`NtWriteVirtualMemory`, `NtCreateThreadEx`, etc.)
- per-PID injection chain (`alloc -> write -> protect -> thread`)
- direct syscall/evasion keywords (`hellsgate`, `syswhispers`, `syscall stub`)
- hook-evasion markers (`unhook`, `restore ntdll`)
- RWX markers

## Output

Generates markdown report with:

- risk verdict and score
- global metrics
- baseline comparison metrics and suspicious call deltas (when `--baseline` is used)
- top syscall/API frequencies
- MITRE ATT&CK technique mapping section
- ranked findings with line references

Also supports JSON output for SOC pipeline ingestion via `--json`.

Machine-readable finding IDs are emitted in both markdown and JSON for SIEM correlation.

Examples: `SP-INJECT-CHAIN`, `SP-EVASION-DIRECT`, `SP-BL-RATIO`.

## Next upgrades

- per-process timeline output
- ATT&CK sub-technique confidence scoring
- dedup + aggregation for large enterprise traces
