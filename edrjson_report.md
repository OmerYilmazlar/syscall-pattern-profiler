# Syscall Pattern Profile

Input trace: .\sample_trace_edrjson.txt
Parser profile: edrjson
Policy source: <default>
Risk verdict: **MEDIUM**
Risk score: **18**

## Metrics

- Total lines: 6
- Parsed syscall/API events: 4
- Suspicious calls: 4
- Injection-chain PID hits: 1
- Direct syscall markers: 0
- Unhook markers: 1
- RWX markers: 1

## Policy Snapshot

- suspicious_call=1, direct_syscall=4, unhook=3, rwx=3, injection_chain=8
- ratio_threshold=40% (min_calls=20), ratio_bonus=4
- verdicts: MEDIUM>=12, HIGH>=25

## Top Calls

- ntcreatethreadex: 1
- ntallocatevirtualmemory: 1
- ntwritevirtualmemory: 1
- ntprotectvirtualmemory: 1

## MITRE ATT&CK Mapping

- T1055 - Process Injection: Injection-related call chains and remote-thread style APIs observed.
- T1106 - Native API: Trace indicates heavy reliance on low-level NT/native APIs.
- T1562.001 - Impair Defenses: Disable or Modify Tools: Unhook/restore-ntdll style markers suggest defense-evasion behavior.

## Findings

- [S5] SP-INJECT-CHAIN: Injection chain in PID 4120 (alloc->write->protect->thread)
- [S3] SP-MEM-RWX line 1: RWX memory protection marker
- [S3] SP-EVASION-UNHOOK line 5: Hook evasion/unhook marker
