# Syscall Pattern Profile

Input trace: .\sample_trace.txt
Parser profile: auto
Policy source: .\policy_default.json
Risk verdict: **HIGH**
Risk score: **32**

## Metrics

- Total lines: 17
- Parsed syscall/API events: 8
- Suspicious calls: 6
- Injection-chain PID hits: 1
- Direct syscall markers: 1
- Unhook markers: 1
- RWX markers: 1

## Policy Snapshot

- suspicious_call=1, direct_syscall=4, unhook=3, rwx=3, injection_chain=8
- ratio_threshold=40% (min_calls=20), ratio_bonus=4
- verdicts: MEDIUM>=12, HIGH>=25

## Baseline Comparison

- Baseline trace: .\known_good_trace.txt
- Suspicious ratio: 75% (current) vs 0% (baseline)
- Injection-chain delta: 1
- Score adjustment from baseline mode: 8
- Top suspicious call increases:
  - ntwritevirtualmemory: +1
  - ntprotectvirtualmemory: +1
  - writeprocessmemory: +1
  - ntcreatethreadex: +1
  - createremotethread: +1
  - ntallocatevirtualmemory: +1

## Top Calls

- ntqueryinformationprocess: 1
- ntreadfile: 1
- ntwritevirtualmemory: 1
- ntprotectvirtualmemory: 1
- writeprocessmemory: 1
- ntcreatethreadex: 1
- createremotethread: 1
- ntallocatevirtualmemory: 1

## MITRE ATT&CK Mapping

- T1055 - Process Injection: Injection-related call chains and remote-thread style APIs observed.
- T1106 - Native API: Trace indicates heavy reliance on low-level NT/native APIs.
- T1562.001 - Impair Defenses: Disable or Modify Tools: Unhook/restore-ntdll style markers suggest defense-evasion behavior.
- T1027 - Obfuscated/Compressed Files and Information: Direct-syscall framework markers indicate evasion through indirect execution patterns.
- T1059 - Command and Scripting Interpreter: Baseline comparison shows suspicious execution behavior increase requiring triage.

## Findings

- [S5] SP-BL-CHAIN: Baseline delta: +1 injection-chain PID(s)
- [S5] SP-INJECT-CHAIN: Injection chain in PID 4120 (alloc->write->protect->thread)
- [S4] SP-EVASION-DIRECT line 12: Direct-syscall/evasion keyword
- [S3] SP-BL-CALLS: Baseline delta: multiple suspicious API call increases
- [S3] SP-MEM-RWX line 6: RWX memory protection marker
- [S3] SP-EVASION-UNHOOK line 13: Hook evasion/unhook marker
