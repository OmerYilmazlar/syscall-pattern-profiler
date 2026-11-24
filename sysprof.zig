const std = @import("std");

const Finding = struct {
    id: []const u8,
    severity: u8,
    line_no: usize,
    text: []u8,
};

const Technique = struct {
    id: []const u8,
    name: []const u8,
    rationale: []const u8,
};

const PidState = struct {
    saw_alloc: bool = false,
    saw_write: bool = false,
    saw_protect: bool = false,
    saw_thread: bool = false,
};

const SysCount = struct {
    name: []const u8,
    count: usize,
};

const CallDelta = struct {
    name: []const u8,
    delta: isize,
};

const TraceStats = struct {
    total_lines: usize = 0,
    parsed_calls: usize = 0,
    suspicious_calls: usize = 0,
    chain_hits: usize = 0,
    direct_syscall_hits: usize = 0,
    unhook_hits: usize = 0,
    rwx_hits: usize = 0,
    score: i32 = 0,
};

const BaselineSummary = struct {
    enabled: bool,
    path: []const u8,
    score_adjustment: i32,
    suspicious_ratio_current: usize,
    suspicious_ratio_baseline: usize,
    chain_delta: isize,
};

const ParserProfile = enum {
    auto,
    kv,
    csv,
    edrjson,
};

const ParsedEvent = struct {
    pid: ?i32 = null,
    call_name: ?[]const u8 = null,
};

const ScoringPolicy = struct {
    weight_suspicious_call: i32 = 1,
    weight_direct_syscall: i32 = 4,
    weight_unhook: i32 = 3,
    weight_rwx: i32 = 3,
    weight_injection_chain: i32 = 8,
    weight_high_ratio: i32 = 4,

    threshold_ratio_min_calls: usize = 20,
    threshold_ratio_pct: usize = 40,

    baseline_weight_chain_delta: i32 = 5,
    baseline_ratio_increase_pct: usize = 15,
    baseline_weight_ratio_delta: i32 = 4,
    baseline_multi_increase_min: usize = 3,
    baseline_weight_multi_increase: i32 = 3,

    verdict_medium: i32 = 12,
    verdict_high: i32 = 25,
};

const Cli = struct {
    trace_path: []u8,
    out_path: []u8,
    json_path: ?[]u8,
    baseline_path: ?[]u8,
    policy_path: ?[]u8,
    profile: ParserProfile,
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const cli = try parseArgs(allocator);
    defer freeCli(cli, allocator);

    try analyzeTrace(allocator, cli);
}

fn parseArgs(allocator: std.mem.Allocator) !Cli {
    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();

    _ = args.next();

    var out_path = try allocator.dupe(u8, "syscall_profile_report.md");
    errdefer allocator.free(out_path);

    var json_path: ?[]u8 = null;
    var baseline_path: ?[]u8 = null;
    var policy_path: ?[]u8 = null;
    var profile: ParserProfile = .auto;

    const trace_arg = args.next() orelse {
        printUsage();
        std.process.exit(1);
    };

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            printUsage();
            std.process.exit(0);
        }
        if (std.mem.eql(u8, arg, "-o") or std.mem.eql(u8, arg, "--out")) {
            const v = args.next() orelse return error.MissingOutputPath;
            allocator.free(out_path);
            out_path = try allocator.dupe(u8, v);
            continue;
        }
        if (std.mem.eql(u8, arg, "--json")) {
            const v = args.next() orelse return error.MissingJsonPath;
            if (json_path) |old| allocator.free(old);
            json_path = try allocator.dupe(u8, v);
            continue;
        }
        if (std.mem.eql(u8, arg, "--baseline")) {
            const v = args.next() orelse return error.MissingBaselinePath;
            if (baseline_path) |old| allocator.free(old);
            baseline_path = try allocator.dupe(u8, v);
            continue;
        }
        if (std.mem.eql(u8, arg, "--policy")) {
            const v = args.next() orelse return error.MissingPolicyPath;
            if (policy_path) |old| allocator.free(old);
            policy_path = try allocator.dupe(u8, v);
            continue;
        }
        if (std.mem.eql(u8, arg, "--profile")) {
            const v = args.next() orelse return error.MissingProfile;
            profile = parseProfile(v) orelse return error.InvalidProfile;
            continue;
        }
    }

    return .{
        .trace_path = try allocator.dupe(u8, trace_arg),
        .out_path = out_path,
        .json_path = json_path,
        .baseline_path = baseline_path,
        .policy_path = policy_path,
        .profile = profile,
    };
}

fn freeCli(cli: Cli, allocator: std.mem.Allocator) void {
    allocator.free(cli.trace_path);
    allocator.free(cli.out_path);
    if (cli.json_path) |p| allocator.free(p);
    if (cli.baseline_path) |p| allocator.free(p);
    if (cli.policy_path) |p| allocator.free(p);
}

fn parseProfile(s: []const u8) ?ParserProfile {
    if (asciiEqIgnoreCase(s, "auto")) return .auto;
    if (asciiEqIgnoreCase(s, "kv")) return .kv;
    if (asciiEqIgnoreCase(s, "csv")) return .csv;
    if (asciiEqIgnoreCase(s, "edrjson")) return .edrjson;
    return null;
}

fn profileToString(p: ParserProfile) []const u8 {
    return switch (p) {
        .auto => "auto",
        .kv => "kv",
        .csv => "csv",
        .edrjson => "edrjson",
    };
}

fn printUsage() void {
    std.debug.print("Usage: sysprof <trace.txt> [--out report.md] [--json out.json] [--baseline known_good.txt] [--policy policy.json] [--profile auto|kv|csv|edrjson]\n\n", .{});
    std.debug.print("Profiles syscall/API trace lines for likely injection and evasion behavior.\n", .{});
}

fn analyzeTrace(allocator: std.mem.Allocator, cli: Cli) !void {
    const policy = if (cli.policy_path) |pp|
        try loadPolicyFromJson(allocator, pp)
    else
        ScoringPolicy{};

    const trace_data = std.fs.cwd().readFileAlloc(allocator, cli.trace_path, 32 * 1024 * 1024) catch |err| {
        std.debug.print("[!] Failed to read {s}: {s}\n", .{ cli.trace_path, @errorName(err) });
        return;
    };
    defer allocator.free(trace_data);

    var findings: std.ArrayList(Finding) = .empty;
    defer freeFindings(&findings, allocator);

    var current_counts = std.StringHashMap(usize).init(allocator);
    defer freeSyscallCountMap(&current_counts, allocator);
    var current_stats = try profileTraceData(allocator, trace_data, cli.profile, policy, true, &findings, &current_counts);

    var baseline_summary = BaselineSummary{
        .enabled = false,
        .path = "",
        .score_adjustment = 0,
        .suspicious_ratio_current = suspiciousRatio(current_stats),
        .suspicious_ratio_baseline = 0,
        .chain_delta = 0,
    };
    var baseline_top_increases: std.ArrayList(CallDelta) = .empty;
    defer baseline_top_increases.deinit(allocator);

    if (cli.baseline_path) |baseline_path| {
        const baseline_data = std.fs.cwd().readFileAlloc(allocator, baseline_path, 32 * 1024 * 1024) catch |err| {
            std.debug.print("[!] Failed to read baseline {s}: {s}\n", .{ baseline_path, @errorName(err) });
            return;
        };
        defer allocator.free(baseline_data);

        var baseline_counts = std.StringHashMap(usize).init(allocator);
        defer freeSyscallCountMap(&baseline_counts, allocator);
        var baseline_findings_unused: std.ArrayList(Finding) = .empty;
        defer baseline_findings_unused.deinit(allocator);

        const baseline_stats = try profileTraceData(
            allocator,
            baseline_data,
            cli.profile,
            policy,
            false,
            &baseline_findings_unused,
            &baseline_counts,
        );

        baseline_summary.enabled = true;
        baseline_summary.path = baseline_path;
        baseline_summary.suspicious_ratio_baseline = suspiciousRatio(baseline_stats);
        baseline_summary.chain_delta = @as(isize, @intCast(current_stats.chain_hits)) - @as(isize, @intCast(baseline_stats.chain_hits));

        if (baseline_summary.chain_delta > 0) {
            const add = @as(i32, @intCast(baseline_summary.chain_delta)) * policy.baseline_weight_chain_delta;
            current_stats.score += add;
            baseline_summary.score_adjustment += add;
            try addFindingFmt(&findings, allocator, "SP-BL-CHAIN", 5, 0, "Baseline delta: +{d} injection-chain PID(s)", .{baseline_summary.chain_delta});
        }

        if (current_stats.parsed_calls >= 10 and baseline_summary.suspicious_ratio_current >= baseline_summary.suspicious_ratio_baseline + policy.baseline_ratio_increase_pct) {
            current_stats.score += policy.baseline_weight_ratio_delta;
            baseline_summary.score_adjustment += policy.baseline_weight_ratio_delta;
            try addFindingFmt(
                &findings,
                allocator,
                "SP-BL-RATIO",
                4,
                0,
                "Baseline delta: suspicious-call ratio increased from {d}% to {d}%",
                .{ baseline_summary.suspicious_ratio_baseline, baseline_summary.suspicious_ratio_current },
            );
        }

        try collectCallIncreases(&current_counts, &baseline_counts, &baseline_top_increases, allocator);
        sortCallDeltas(baseline_top_increases.items);
        if (baseline_top_increases.items.len >= policy.baseline_multi_increase_min) {
            current_stats.score += policy.baseline_weight_multi_increase;
            baseline_summary.score_adjustment += policy.baseline_weight_multi_increase;
            try addFindingFmt(&findings, allocator, "SP-BL-CALLS", 3, 0, "Baseline delta: multiple suspicious API call increases", .{});
        }
    }

    const verdict = scoreToVerdict(current_stats.score, policy);

    var top_calls: std.ArrayList(SysCount) = .empty;
    defer top_calls.deinit(allocator);
    try collectSysCounts(&current_counts, &top_calls, allocator);
    sortSysCounts(top_calls.items);

    var techniques: std.ArrayList(Technique) = .empty;
    defer techniques.deinit(allocator);
    try buildMitreMappings(&techniques, allocator, current_stats, baseline_summary);

    sortFindings(findings.items);
    try writeReport(
        cli.out_path,
        cli.trace_path,
        findings.items,
        top_calls.items,
        techniques.items,
        baseline_summary,
        baseline_top_increases.items,
        current_stats,
        verdict,
        cli.profile,
        policy,
        if (cli.policy_path) |p| p else "<default>",
    );

    if (cli.json_path) |jp| {
        try writeJsonReport(
            jp,
            cli.trace_path,
            findings.items,
            top_calls.items,
            techniques.items,
            baseline_summary,
            baseline_top_increases.items,
            current_stats,
            verdict,
            cli.profile,
            policy,
            if (cli.policy_path) |p| p else "<default>",
        );
        std.debug.print("JSON written: {s}\n", .{jp});
    }

    std.debug.print("Report written: {s}\n", .{cli.out_path});
    std.debug.print("Profile: {s} | Policy: {s}\n", .{ profileToString(cli.profile), if (cli.policy_path) |p| p else "<default>" });
    std.debug.print("Trace lines: {d} | Calls parsed: {d}\n", .{ current_stats.total_lines, current_stats.parsed_calls });
    std.debug.print("Suspicious calls: {d} | Chain hits: {d}\n", .{ current_stats.suspicious_calls, current_stats.chain_hits });
    std.debug.print("Risk score: {d} ({s})\n", .{ current_stats.score, verdict });
}

fn profileTraceData(
    allocator: std.mem.Allocator,
    data: []const u8,
    profile: ParserProfile,
    policy: ScoringPolicy,
    emit_findings: bool,
    findings: *std.ArrayList(Finding),
    syscall_counts: *std.StringHashMap(usize),
) !TraceStats {
    var stats = TraceStats{};
    var pid_states = std.AutoHashMap(i32, PidState).init(allocator);
    defer pid_states.deinit();

    var line_it = std.mem.splitScalar(u8, data, '\n');
    while (line_it.next()) |line_raw| {
        stats.total_lines += 1;
        const line = std.mem.trim(u8, line_raw, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;

        const evt = parseEventLine(line, profile);

        if (evt.call_name) |call_name| {
            stats.parsed_calls += 1;
            try bumpCount(syscall_counts, allocator, call_name);

            if (isSuspiciousCall(call_name)) {
                stats.suspicious_calls += 1;
                stats.score += policy.weight_suspicious_call;
            }

            if (evt.pid) |pid| {
                var ps = pid_states.get(pid) orelse PidState{};
                updatePidState(call_name, &ps);
                try pid_states.put(pid, ps);
            }
        }

        if (containsAnyCi(line, &[_][]const u8{ "hellsgate", "halosgate", "syswhispers", "direct syscall", "syscall stub" })) {
            stats.direct_syscall_hits += 1;
            stats.score += policy.weight_direct_syscall;
            if (emit_findings) try addFindingFmt(findings, allocator, "SP-EVASION-DIRECT", 4, stats.total_lines, "Direct-syscall/evasion keyword", .{});
        }

        if (containsAnyCi(line, &[_][]const u8{ "unhook", "ntdll patch", "restore ntdll" })) {
            stats.unhook_hits += 1;
            stats.score += policy.weight_unhook;
            if (emit_findings) try addFindingFmt(findings, allocator, "SP-EVASION-UNHOOK", 3, stats.total_lines, "Hook evasion/unhook marker", .{});
        }

        if (containsAnyCi(line, &[_][]const u8{ "rwx", "page_execute_readwrite", "execute_readwrite" })) {
            stats.rwx_hits += 1;
            stats.score += policy.weight_rwx;
            if (emit_findings) try addFindingFmt(findings, allocator, "SP-MEM-RWX", 3, stats.total_lines, "RWX memory protection marker", .{});
        }
    }

    var it = pid_states.iterator();
    while (it.next()) |entry| {
        const pid = entry.key_ptr.*;
        const st = entry.value_ptr.*;
        if (st.saw_alloc and st.saw_write and st.saw_protect and st.saw_thread) {
            stats.chain_hits += 1;
            stats.score += policy.weight_injection_chain;
            if (emit_findings) try addFindingFmt(findings, allocator, "SP-INJECT-CHAIN", 5, 0, "Injection chain in PID {d} (alloc->write->protect->thread)", .{pid});
        }
    }

    if (stats.parsed_calls >= policy.threshold_ratio_min_calls and suspiciousRatio(stats) >= policy.threshold_ratio_pct) {
        stats.score += policy.weight_high_ratio;
        if (emit_findings) try addFindingFmt(findings, allocator, "SP-RATIO-HIGH", 4, 0, "High suspicious-call ratio ({d}/{d})", .{ stats.suspicious_calls, stats.parsed_calls });
    }

    return stats;
}

fn parseEventLine(line: []const u8, profile: ParserProfile) ParsedEvent {
    return switch (profile) {
        .kv => parseKvEvent(line),
        .csv => parseCsvEvent(line),
        .edrjson => parseEdrJsonEvent(line),
        .auto => blk: {
            const kv = parseKvEvent(line);
            if (kv.call_name != null) break :blk kv;
            const edr = parseEdrJsonEvent(line);
            if (edr.call_name != null) break :blk edr;
            break :blk parseCsvEvent(line);
        },
    };
}

fn parseKvEvent(line: []const u8) ParsedEvent {
    return .{
        .pid = parsePidKV(line),
        .call_name = extractCallNameKV(line),
    };
}

fn parseCsvEvent(line: []const u8) ParsedEvent {
    if (std.mem.indexOfScalar(u8, line, ',') == null) return .{};

    var ev = ParsedEvent{};
    var it = std.mem.splitScalar(u8, line, ',');
    var col_index: usize = 0;

    while (it.next()) |raw| : (col_index += 1) {
        const col = std.mem.trim(u8, raw, " \t\r\"");
        if (col.len == 0) continue;

        if (ev.pid == null) {
            if (parseIntMaybe(col)) |pid| ev.pid = @intCast(pid);
            if (col_index == 0 and indexOfCi(col, "pid") != null) {
                // likely header line
                return .{};
            }
        }

        if (ev.call_name == null) {
            if (extractCallNameKV(col)) |name| {
                ev.call_name = name;
            } else if (looksLikeCallToken(col)) {
                ev.call_name = col;
            }
        }
    }

    return ev;
}

fn parseEdrJsonEvent(line: []const u8) ParsedEvent {
    if (std.mem.indexOfScalar(u8, line, '{') == null) return .{};

    var ev = ParsedEvent{};
    if (extractJsonIntField(line, "pid")) |pid| ev.pid = @intCast(pid);

    if (extractJsonStringField(line, "syscall")) |v| {
        ev.call_name = v;
        return ev;
    }
    if (extractJsonStringField(line, "api")) |v| {
        ev.call_name = v;
        return ev;
    }
    if (extractJsonStringField(line, "ntapi")) |v| {
        ev.call_name = v;
        return ev;
    }
    if (extractJsonStringField(line, "function")) |v| {
        ev.call_name = v;
    }

    return ev;
}

fn looksLikeCallToken(tok: []const u8) bool {
    if (tok.len < 3) return false;
    return containsAnyCi(tok, &[_][]const u8{ "nt", "virtual", "thread", "processmemory", "syscall" });
}

fn parsePidKV(line: []const u8) ?i32 {
    if (extractIntAfter(line, "pid=")) |v| return @intCast(v);
    if (extractIntAfter(line, "pid:")) |v| return @intCast(v);
    return null;
}

fn extractIntAfter(line: []const u8, key: []const u8) ?usize {
    const idx = indexOfCi(line, key) orelse return null;
    var i = idx + key.len;
    if (i >= line.len) return null;

    var num: usize = 0;
    var saw_digit = false;
    while (i < line.len) : (i += 1) {
        const c = line[i];
        if (c >= '0' and c <= '9') {
            saw_digit = true;
            num = num * 10 + (c - '0');
        } else if (saw_digit) {
            break;
        } else if (c == ' ' or c == '\t') {
            continue;
        } else {
            return null;
        }
    }

    if (!saw_digit) return null;
    return num;
}

fn parseIntMaybe(s: []const u8) ?usize {
    var i: usize = 0;
    var n: usize = 0;
    var saw = false;
    while (i < s.len) : (i += 1) {
        const c = s[i];
        if (c >= '0' and c <= '9') {
            saw = true;
            n = n * 10 + (c - '0');
        } else if (saw) {
            return n;
        } else {
            return null;
        }
    }
    return if (saw) n else null;
}

fn extractCallNameKV(line: []const u8) ?[]const u8 {
    if (extractTokenValue(line, "syscall=")) |v| return v;
    if (extractTokenValue(line, "api=")) |v| return v;
    if (extractTokenValue(line, "ntapi=")) |v| return v;
    return null;
}

fn extractTokenValue(line: []const u8, key: []const u8) ?[]const u8 {
    const idx = indexOfCi(line, key) orelse return null;
    var start = idx + key.len;
    while (start < line.len and (line[start] == ' ' or line[start] == '"')) : (start += 1) {}
    if (start >= line.len) return null;

    var end = start;
    while (end < line.len) : (end += 1) {
        const c = line[end];
        if (c == ' ' or c == '\t' or c == '"' or c == ',' or c == ';') break;
    }

    if (end <= start) return null;
    return line[start..end];
}

fn extractJsonIntField(line: []const u8, key: []const u8) ?usize {
    var keybuf: [64]u8 = undefined;
    const needle = std.fmt.bufPrint(&keybuf, "\"{s}\"", .{key}) catch return null;
    const key_idx = std.mem.indexOf(u8, line, needle) orelse return null;
    const colon_idx = std.mem.indexOfPos(u8, line, key_idx + needle.len, ":") orelse return null;

    var i = colon_idx + 1;
    while (i < line.len and (line[i] == ' ' or line[i] == '\t')) : (i += 1) {}

    var n: usize = 0;
    var saw = false;
    while (i < line.len) : (i += 1) {
        const c = line[i];
        if (c >= '0' and c <= '9') {
            saw = true;
            n = n * 10 + (c - '0');
        } else if (saw) {
            break;
        } else {
            return null;
        }
    }
    return if (saw) n else null;
}

fn extractJsonStringField(line: []const u8, key: []const u8) ?[]const u8 {
    var keybuf: [64]u8 = undefined;
    const needle = std.fmt.bufPrint(&keybuf, "\"{s}\"", .{key}) catch return null;
    const key_idx = std.mem.indexOf(u8, line, needle) orelse return null;
    const colon_idx = std.mem.indexOfPos(u8, line, key_idx + needle.len, ":") orelse return null;

    var i = colon_idx + 1;
    while (i < line.len and (line[i] == ' ' or line[i] == '\t')) : (i += 1) {}
    if (i >= line.len or line[i] != '"') return null;
    i += 1;

    const start = i;
    while (i < line.len) : (i += 1) {
        if (line[i] == '"' and line[i - 1] != '\\') {
            if (i > start) return line[start..i];
            return null;
        }
    }
    return null;
}

fn bumpCount(map: *std.StringHashMap(usize), allocator: std.mem.Allocator, name: []const u8) !void {
    const lower = try allocator.dupe(u8, name);
    errdefer allocator.free(lower);
    asciiToLowerInPlace(lower);

    if (map.getPtr(lower)) |ptr| {
        ptr.* += 1;
        allocator.free(lower);
        return;
    }

    try map.put(lower, 1);
}

fn asciiToLowerInPlace(buf: []u8) void {
    for (buf) |*c| c.* = std.ascii.toLower(c.*);
}

fn updatePidState(call_name: []const u8, ps: *PidState) void {
    if (containsAnyCi(call_name, &[_][]const u8{ "ntallocatevirtualmemory", "virtualalloc", "virtualallocex" })) ps.saw_alloc = true;
    if (containsAnyCi(call_name, &[_][]const u8{ "ntwritevirtualmemory", "writeprocessmemory" })) ps.saw_write = true;
    if (containsAnyCi(call_name, &[_][]const u8{ "ntprotectvirtualmemory", "virtualprotect", "virtualprotectex" })) ps.saw_protect = true;
    if (containsAnyCi(call_name, &[_][]const u8{ "ntcreatethreadex", "createremotethread", "ntqueueapcthread", "rtlcreateuserthread" })) ps.saw_thread = true;
}

fn isSuspiciousCall(call_name: []const u8) bool {
    return containsAnyCi(call_name, &[_][]const u8{
        "ntallocatevirtualmemory",
        "ntwritevirtualmemory",
        "ntprotectvirtualmemory",
        "ntcreatethreadex",
        "ntqueueapcthread",
        "ntmapviewofsection",
        "ntunmapviewofsection",
        "ntsetcontextthread",
        "ntresumethread",
        "writeprocessmemory",
        "createremotethread",
    });
}

fn collectSysCounts(map: *std.StringHashMap(usize), out: *std.ArrayList(SysCount), allocator: std.mem.Allocator) !void {
    var it = map.iterator();
    while (it.next()) |entry| {
        try out.append(allocator, .{ .name = entry.key_ptr.*, .count = entry.value_ptr.* });
    }
}

fn collectCallIncreases(
    current: *std.StringHashMap(usize),
    baseline: *std.StringHashMap(usize),
    out: *std.ArrayList(CallDelta),
    allocator: std.mem.Allocator,
) !void {
    var it = current.iterator();
    while (it.next()) |entry| {
        const name = entry.key_ptr.*;
        if (!isSuspiciousCall(name)) continue;

        const cur = entry.value_ptr.*;
        const base = baseline.get(name) orelse 0;
        if (cur > base) {
            try out.append(allocator, .{ .name = name, .delta = @as(isize, @intCast(cur - base)) });
        }
    }
}

fn sortCallDeltas(items: []CallDelta) void {
    if (items.len < 2) return;
    var i: usize = 0;
    while (i < items.len - 1) : (i += 1) {
        var best = i;
        var j: usize = i + 1;
        while (j < items.len) : (j += 1) {
            if (items[j].delta > items[best].delta) best = j;
        }
        if (best != i) {
            const tmp = items[i];
            items[i] = items[best];
            items[best] = tmp;
        }
    }
}

fn buildMitreMappings(
    out: *std.ArrayList(Technique),
    allocator: std.mem.Allocator,
    stats: TraceStats,
    baseline: BaselineSummary,
) !void {
    if (stats.chain_hits > 0 or stats.suspicious_calls >= 3) {
        try pushTechnique(out, allocator, .{ .id = "T1055", .name = "Process Injection", .rationale = "Injection-related call chains and remote-thread style APIs observed." });
    }
    if (stats.direct_syscall_hits > 0 or stats.suspicious_calls > 0) {
        try pushTechnique(out, allocator, .{ .id = "T1106", .name = "Native API", .rationale = "Trace indicates heavy reliance on low-level NT/native APIs." });
    }
    if (stats.unhook_hits > 0) {
        try pushTechnique(out, allocator, .{ .id = "T1562.001", .name = "Impair Defenses: Disable or Modify Tools", .rationale = "Unhook/restore-ntdll style markers suggest defense-evasion behavior." });
    }
    if (stats.direct_syscall_hits > 0) {
        try pushTechnique(out, allocator, .{ .id = "T1027", .name = "Obfuscated/Compressed Files and Information", .rationale = "Direct-syscall framework markers indicate evasion through indirect execution patterns." });
    }
    if (baseline.enabled and baseline.score_adjustment > 0) {
        try pushTechnique(out, allocator, .{ .id = "T1059", .name = "Command and Scripting Interpreter", .rationale = "Baseline comparison shows suspicious execution behavior increase requiring triage." });
    }
}

fn pushTechnique(out: *std.ArrayList(Technique), allocator: std.mem.Allocator, t: Technique) !void {
    for (out.items) |existing| {
        if (std.mem.eql(u8, existing.id, t.id)) return;
    }
    try out.append(allocator, t);
}

fn suspiciousRatio(stats: TraceStats) usize {
    if (stats.parsed_calls == 0) return 0;
    return stats.suspicious_calls * 100 / stats.parsed_calls;
}

fn scoreToVerdict(score: i32, policy: ScoringPolicy) []const u8 {
    if (score >= policy.verdict_high) return "HIGH";
    if (score >= policy.verdict_medium) return "MEDIUM";
    return "LOW";
}

fn loadPolicyFromJson(allocator: std.mem.Allocator, path: []const u8) !ScoringPolicy {
    var p = ScoringPolicy{};
    const data = std.fs.cwd().readFileAlloc(allocator, path, 256 * 1024) catch |err| {
        std.debug.print("[!] Failed to read policy {s}: {s}\n", .{ path, @errorName(err) });
        return p;
    };
    defer allocator.free(data);

    applyPolicyI32(data, "weight_suspicious_call", &p.weight_suspicious_call);
    applyPolicyI32(data, "weight_direct_syscall", &p.weight_direct_syscall);
    applyPolicyI32(data, "weight_unhook", &p.weight_unhook);
    applyPolicyI32(data, "weight_rwx", &p.weight_rwx);
    applyPolicyI32(data, "weight_injection_chain", &p.weight_injection_chain);
    applyPolicyI32(data, "weight_high_ratio", &p.weight_high_ratio);

    applyPolicyUsize(data, "threshold_ratio_min_calls", &p.threshold_ratio_min_calls);
    applyPolicyUsize(data, "threshold_ratio_pct", &p.threshold_ratio_pct);

    applyPolicyI32(data, "baseline_weight_chain_delta", &p.baseline_weight_chain_delta);
    applyPolicyUsize(data, "baseline_ratio_increase_pct", &p.baseline_ratio_increase_pct);
    applyPolicyI32(data, "baseline_weight_ratio_delta", &p.baseline_weight_ratio_delta);
    applyPolicyUsize(data, "baseline_multi_increase_min", &p.baseline_multi_increase_min);
    applyPolicyI32(data, "baseline_weight_multi_increase", &p.baseline_weight_multi_increase);

    applyPolicyI32(data, "verdict_medium", &p.verdict_medium);
    applyPolicyI32(data, "verdict_high", &p.verdict_high);

    return p;
}

fn applyPolicyI32(data: []const u8, key: []const u8, out: *i32) void {
    if (extractJsonNumber(data, key)) |n| out.* = @intCast(n);
}

fn applyPolicyUsize(data: []const u8, key: []const u8, out: *usize) void {
    if (extractJsonNumber(data, key)) |n| {
        if (n >= 0) out.* = @intCast(n);
    }
}

fn extractJsonNumber(data: []const u8, key: []const u8) ?i64 {
    var buf: [96]u8 = undefined;
    const needle = std.fmt.bufPrint(&buf, "\"{s}\"", .{key}) catch return null;
    const key_idx = std.mem.indexOf(u8, data, needle) orelse return null;
    const colon_idx = std.mem.indexOfPos(u8, data, key_idx + needle.len, ":") orelse return null;

    var i = colon_idx + 1;
    while (i < data.len and (data[i] == ' ' or data[i] == '\t' or data[i] == '\n' or data[i] == '\r')) : (i += 1) {}
    if (i >= data.len) return null;

    var sign: i64 = 1;
    if (data[i] == '-') {
        sign = -1;
        i += 1;
    }

    var num: i64 = 0;
    var saw = false;
    while (i < data.len) : (i += 1) {
        const c = data[i];
        if (c >= '0' and c <= '9') {
            saw = true;
            num = num * 10 + @as(i64, c - '0');
        } else if (saw) {
            break;
        } else {
            return null;
        }
    }

    return if (saw) num * sign else null;
}

fn writeReport(
    out_path: []const u8,
    trace_path: []const u8,
    findings: []const Finding,
    top_calls: []const SysCount,
    techniques: []const Technique,
    baseline: BaselineSummary,
    call_increases: []const CallDelta,
    stats: TraceStats,
    verdict: []const u8,
    profile: ParserProfile,
    policy: ScoringPolicy,
    policy_label: []const u8,
) !void {
    const out = try std.fs.cwd().createFile(out_path, .{ .truncate = true });
    defer out.close();

    var wbuf: [4096]u8 = undefined;
    var writer = out.writer(&wbuf);
    const w = &writer.interface;

    try w.print("# Syscall Pattern Profile\n\n", .{});
    try w.print("Input trace: {s}\n", .{trace_path});
    try w.print("Parser profile: {s}\n", .{profileToString(profile)});
    try w.print("Policy source: {s}\n", .{policy_label});
    try w.print("Risk verdict: **{s}**\n", .{verdict});
    try w.print("Risk score: **{d}**\n\n", .{stats.score});

    try w.print("## Metrics\n\n", .{});
    try w.print("- Total lines: {d}\n", .{stats.total_lines});
    try w.print("- Parsed syscall/API events: {d}\n", .{stats.parsed_calls});
    try w.print("- Suspicious calls: {d}\n", .{stats.suspicious_calls});
    try w.print("- Injection-chain PID hits: {d}\n", .{stats.chain_hits});
    try w.print("- Direct syscall markers: {d}\n", .{stats.direct_syscall_hits});
    try w.print("- Unhook markers: {d}\n", .{stats.unhook_hits});
    try w.print("- RWX markers: {d}\n\n", .{stats.rwx_hits});

    try w.print("## Policy Snapshot\n\n", .{});
    try w.print("- suspicious_call={d}, direct_syscall={d}, unhook={d}, rwx={d}, injection_chain={d}\n", .{ policy.weight_suspicious_call, policy.weight_direct_syscall, policy.weight_unhook, policy.weight_rwx, policy.weight_injection_chain });
    try w.print("- ratio_threshold={d}% (min_calls={d}), ratio_bonus={d}\n", .{ policy.threshold_ratio_pct, policy.threshold_ratio_min_calls, policy.weight_high_ratio });
    try w.print("- verdicts: MEDIUM>={d}, HIGH>={d}\n\n", .{ policy.verdict_medium, policy.verdict_high });

    if (baseline.enabled) {
        try w.print("## Baseline Comparison\n\n", .{});
        try w.print("- Baseline trace: {s}\n", .{baseline.path});
        try w.print("- Suspicious ratio: {d}% (current) vs {d}% (baseline)\n", .{ baseline.suspicious_ratio_current, baseline.suspicious_ratio_baseline });
        try w.print("- Injection-chain delta: {d}\n", .{baseline.chain_delta});
        try w.print("- Score adjustment from baseline mode: {d}\n", .{baseline.score_adjustment});

        if (call_increases.len > 0) {
            try w.print("- Top suspicious call increases:\n", .{});
            const max_inc = @min(@as(usize, 8), call_increases.len);
            var i_inc: usize = 0;
            while (i_inc < max_inc) : (i_inc += 1) {
                try w.print("  - {s}: +{d}\n", .{ call_increases[i_inc].name, call_increases[i_inc].delta });
            }
        }
        try w.print("\n", .{});
    }

    try w.print("## Top Calls\n\n", .{});
    const max_calls = @min(@as(usize, 12), top_calls.len);
    var i: usize = 0;
    while (i < max_calls) : (i += 1) {
        try w.print("- {s}: {d}\n", .{ top_calls[i].name, top_calls[i].count });
    }

    try w.print("\n## MITRE ATT&CK Mapping\n\n", .{});
    if (techniques.len == 0) {
        try w.print("No mapped techniques from current heuristics.\n", .{});
    } else {
        for (techniques) |t| {
            try w.print("- {s} - {s}: {s}\n", .{ t.id, t.name, t.rationale });
        }
    }

    try w.print("\n## Findings\n\n", .{});
    if (findings.len == 0) {
        try w.print("No notable findings.\n", .{});
    } else {
        const max_findings = @min(@as(usize, 25), findings.len);
        var f: usize = 0;
        while (f < max_findings) : (f += 1) {
            const item = findings[f];
            if (item.line_no == 0) {
                try w.print("- [S{d}] {s}: {s}\n", .{ item.severity, item.id, item.text });
            } else {
                try w.print("- [S{d}] {s} line {d}: {s}\n", .{ item.severity, item.id, item.line_no, item.text });
            }
        }
    }

    try w.flush();
}

fn writeJsonReport(
    out_path: []const u8,
    trace_path: []const u8,
    findings: []const Finding,
    top_calls: []const SysCount,
    techniques: []const Technique,
    baseline: BaselineSummary,
    call_increases: []const CallDelta,
    stats: TraceStats,
    verdict: []const u8,
    profile: ParserProfile,
    policy: ScoringPolicy,
    policy_label: []const u8,
) !void {
    const out = try std.fs.cwd().createFile(out_path, .{ .truncate = true });
    defer out.close();

    var bw: [4096]u8 = undefined;
    var writer = out.writer(&bw);
    const w = &writer.interface;

    try w.writeAll("{\n");
    try w.writeAll("  \"trace\": ");
    try writeJsonString(w, trace_path);
    try w.writeAll(",\n  \"profile\": ");
    try writeJsonString(w, profileToString(profile));
    try w.writeAll(",\n  \"policy_source\": ");
    try writeJsonString(w, policy_label);
    try w.print(",\n  \"verdict\": \"{s}\",\n  \"score\": {d},\n", .{ verdict, stats.score });

    try w.writeAll("  \"policy\": {\n");
    try w.print("    \"weight_suspicious_call\": {d},\n", .{policy.weight_suspicious_call});
    try w.print("    \"weight_direct_syscall\": {d},\n", .{policy.weight_direct_syscall});
    try w.print("    \"weight_unhook\": {d},\n", .{policy.weight_unhook});
    try w.print("    \"weight_rwx\": {d},\n", .{policy.weight_rwx});
    try w.print("    \"weight_injection_chain\": {d},\n", .{policy.weight_injection_chain});
    try w.print("    \"threshold_ratio_pct\": {d},\n", .{policy.threshold_ratio_pct});
    try w.print("    \"threshold_ratio_min_calls\": {d}\n", .{policy.threshold_ratio_min_calls});
    try w.writeAll("  },\n");

    try w.writeAll("  \"metrics\": {\n");
    try w.print("    \"total_lines\": {d},\n", .{stats.total_lines});
    try w.print("    \"parsed_calls\": {d},\n", .{stats.parsed_calls});
    try w.print("    \"suspicious_calls\": {d},\n", .{stats.suspicious_calls});
    try w.print("    \"chain_hits\": {d},\n", .{stats.chain_hits});
    try w.print("    \"direct_syscall_hits\": {d},\n", .{stats.direct_syscall_hits});
    try w.print("    \"unhook_hits\": {d},\n", .{stats.unhook_hits});
    try w.print("    \"rwx_hits\": {d}\n", .{stats.rwx_hits});
    try w.writeAll("  },\n");

    try w.writeAll("  \"baseline\": {\n");
    try w.print("    \"enabled\": {s},\n", .{if (baseline.enabled) "true" else "false"});
    try w.writeAll("    \"path\": ");
    try writeJsonString(w, baseline.path);
    try w.print(",\n    \"suspicious_ratio_current\": {d},\n", .{baseline.suspicious_ratio_current});
    try w.print("    \"suspicious_ratio_baseline\": {d},\n", .{baseline.suspicious_ratio_baseline});
    try w.print("    \"chain_delta\": {d},\n", .{baseline.chain_delta});
    try w.print("    \"score_adjustment\": {d}\n", .{baseline.score_adjustment});
    try w.writeAll("  },\n");

    try w.writeAll("  \"top_calls\": [");
    var i: usize = 0;
    while (i < top_calls.len) : (i += 1) {
        if (i != 0) try w.writeAll(",");
        try w.writeAll("{\"name\":");
        try writeJsonString(w, top_calls[i].name);
        try w.writeAll(",\"count\":");
        try w.print("{d}", .{top_calls[i].count});
        try w.writeAll("}");
    }
    try w.writeAll("],\n");

    try w.writeAll("  \"call_increases\": [");
    i = 0;
    while (i < call_increases.len) : (i += 1) {
        if (i != 0) try w.writeAll(",");
        try w.writeAll("{\"name\":");
        try writeJsonString(w, call_increases[i].name);
        try w.writeAll(",\"delta\":");
        try w.print("{d}", .{call_increases[i].delta});
        try w.writeAll("}");
    }
    try w.writeAll("],\n");

    try w.writeAll("  \"mitre_attack\": [");
    i = 0;
    while (i < techniques.len) : (i += 1) {
        if (i != 0) try w.writeAll(",");
        try w.writeAll("{\"id\":");
        try writeJsonString(w, techniques[i].id);
        try w.writeAll(",\"name\":");
        try writeJsonString(w, techniques[i].name);
        try w.writeAll(",\"rationale\":");
        try writeJsonString(w, techniques[i].rationale);
        try w.writeAll("}");
    }
    try w.writeAll("],\n");

    try w.writeAll("  \"findings\": [");
    i = 0;
    while (i < findings.len) : (i += 1) {
        if (i != 0) try w.writeAll(",");
        try w.writeAll("{\"id\":");
        try writeJsonString(w, findings[i].id);
        try w.writeAll(",\"severity\":");
        try w.print("{d}", .{findings[i].severity});
        try w.writeAll(",\"line_no\":");
        try w.print("{d}", .{findings[i].line_no});
        try w.writeAll(",\"message\":");
        try writeJsonString(w, findings[i].text);
        try w.writeAll("}");
    }
    try w.writeAll("]\n");
    try w.writeAll("}\n");

    try w.flush();
}

fn writeJsonString(w: *std.Io.Writer, s: []const u8) !void {
    try w.writeAll("\"");
    for (s) |c| {
        switch (c) {
            '"' => try w.writeAll("\\\""),
            '\\' => try w.writeAll("\\\\"),
            '\n' => try w.writeAll("\\n"),
            '\r' => try w.writeAll("\\r"),
            '\t' => try w.writeAll("\\t"),
            else => {
                if (c < 0x20) {
                    try w.print("\\u{X:0>4}", .{@as(u16, c)});
                } else {
                    try w.print("{c}", .{c});
                }
            },
        }
    }
    try w.writeAll("\"");
}

fn addFindingFmt(
    findings: *std.ArrayList(Finding),
    allocator: std.mem.Allocator,
    id: []const u8,
    severity: u8,
    line_no: usize,
    comptime fmt: []const u8,
    args: anytype,
) !void {
    const msg = try std.fmt.allocPrint(allocator, fmt, args);
    try findings.append(allocator, .{ .id = id, .severity = severity, .line_no = line_no, .text = msg });
}

fn sortFindings(items: []Finding) void {
    if (items.len < 2) return;
    var i: usize = 0;
    while (i < items.len - 1) : (i += 1) {
        var best = i;
        var j: usize = i + 1;
        while (j < items.len) : (j += 1) {
            if (isHigherFinding(items[j], items[best])) best = j;
        }
        if (best != i) {
            const tmp = items[i];
            items[i] = items[best];
            items[best] = tmp;
        }
    }
}

fn isHigherFinding(a: Finding, b: Finding) bool {
    if (a.severity != b.severity) return a.severity > b.severity;
    if (a.line_no != b.line_no) return a.line_no < b.line_no;
    return std.mem.lessThan(u8, a.id, b.id);
}

fn sortSysCounts(items: []SysCount) void {
    if (items.len < 2) return;
    var i: usize = 0;
    while (i < items.len - 1) : (i += 1) {
        var best = i;
        var j: usize = i + 1;
        while (j < items.len) : (j += 1) {
            if (items[j].count > items[best].count) best = j;
        }
        if (best != i) {
            const tmp = items[i];
            items[i] = items[best];
            items[best] = tmp;
        }
    }
}

fn containsAnyCi(haystack: []const u8, needles: []const []const u8) bool {
    for (needles) |n| {
        if (indexOfCi(haystack, n) != null) return true;
    }
    return false;
}

fn indexOfCi(haystack: []const u8, needle: []const u8) ?usize {
    if (needle.len == 0 or haystack.len < needle.len) return null;
    var i: usize = 0;
    while (i + needle.len <= haystack.len) : (i += 1) {
        if (asciiEqIgnoreCase(haystack[i .. i + needle.len], needle)) return i;
    }
    return null;
}

fn asciiEqIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var i: usize = 0;
    while (i < a.len) : (i += 1) {
        if (std.ascii.toLower(a[i]) != std.ascii.toLower(b[i])) return false;
    }
    return true;
}

fn freeFindings(findings: *std.ArrayList(Finding), allocator: std.mem.Allocator) void {
    for (findings.items) |f| allocator.free(f.text);
    findings.deinit(allocator);
}

fn freeSyscallCountMap(map: *std.StringHashMap(usize), allocator: std.mem.Allocator) void {
    var it = map.iterator();
    while (it.next()) |entry| {
        allocator.free(entry.key_ptr.*);
    }
    map.deinit();
}
