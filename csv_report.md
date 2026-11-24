# Syscall Pattern Profile

Input trace: .\sample_trace_csv.txt
Parser profile: csv
Policy source: <default>
Risk verdict: **MEDIUM**
Risk score: **19**

## Metrics

- Total lines: 7
- Parsed syscall/API events: 5
- Suspicious calls: 4
- Injection-chain PID hits: 1
- Direct syscall markers: 1
- Unhook markers: 0
- RWX markers: 1

## Policy Snapshot

- suspicious_call=1, direct_syscall=4, unhook=3, rwx=3, injection_chain=8
- ratio_threshold=40% (min_calls=20), ratio_bonus=4
- verdicts: MEDIUM>=12, HIGH>=25

## Top Calls

- ntcreatethreadex: 1
- event: 1
- ntallocatevirtualmemory: 1
- ntwritevirtualmemory: 1
- ntprotectvirtualmemory: 1

## MITRE ATT&CK Mapping

- T1055 - Process Injection: Injection-related call chains and remote-thread style APIs observed.
- T1106 - Native API: Trace indicates heavy reliance on low-level NT/native APIs.
- T1027 - Obfuscated/Compressed Files and Information: Direct-syscall framework markers indicate evasion through indirect execution patterns.

## Findings

- [S5] SP-INJECT-CHAIN: Injection chain in PID 12 (alloc->write->protect->thread)
- [S4] SP-EVASION-DIRECT line 6: Direct-syscall/evasion keyword
- [S3] SP-MEM-RWX line 2: RWX memory protection marker
