/**
 * TypeScript SDK for easy-sandbox.
 *
 * ```ts
 * const sandbox = new Sandbox("/usr/local/bin/easy-sandbox");
 * const result = await sandbox.run({
 *   rootfs: "/srv/rootfs",
 *   workspace: "/srv/work",
 *   policy: "/srv/policies/agent.yaml",
 *   command: ["/bin/sh", "-c", "printf ok > /workspace/result.txt"],
 * });
 * if (result.outcome === "policy_rejected") { ... }
 * ```
 *
 * The SDK only builds an argument vector, runs the launcher and interprets its
 * exit status, failure markers and JSONL record; isolation stays in the
 * launcher.  `canonicalRequest()`, `result.canonical()` and
 * `verified.canonical()` produce the same shapes as the Python SDK, which is
 * what the cross-SDK test compares.
 *
 * The file is dependency free and uses only erasable TypeScript syntax, so it
 * runs directly on Node (`node --experimental-strip-types easysandbox.ts`).
 */

import { spawn } from "node:child_process";
import type { ChildProcess, SpawnOptions } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { pathToFileURL } from "node:url";

export const DEFAULT_TIMEOUT_MS = 30_000;
/** Marks a launcher failure caused by the policy document itself. */
export const POLICY_REJECTED_MARKER = "policy-rejected";
/** Marks a launcher failure caused by an enforcement primitive. */
export const ENFORCEMENT_MARKER = "enforcement-failed";

export type Outcome =
  | "exited"
  | "timeout"
  | "policy_rejected"
  | "enforcement_unavailable"
  | "exec_failed"
  | "setup_failed";

export type VerifyOutcome = "all_passed" | "failed" | "pending" | "rejected";
export type Event = Record<string, unknown>;
export type Json = Record<string, unknown>;

export interface RunRequest {
  rootfs: string;
  workspace: string;
  command: string[];
  policy?: string;
  timeoutMs?: number;
  memoryMib?: number;
  cpuSeconds?: number;
  maxProcesses?: number;
  secure?: boolean;
  proxyAllow?: string[];
  record?: string;
}

export class SandboxError extends Error {}
export class ReportError extends Error {}

interface Spawned {
  child: ChildProcess;
  stdout: Promise<string>;
  stderr: Promise<string>;
}

/** The launcher arguments for one request, in a fixed order. */
export function requestArgv(request: RunRequest): string[] {
  const argv = [
    "run",
    "--rootfs",
    request.rootfs,
    "--workspace",
    request.workspace,
    "--timeout-ms",
    String(request.timeoutMs ?? DEFAULT_TIMEOUT_MS),
  ];
  if (request.memoryMib !== undefined) argv.push("--memory-mib", String(request.memoryMib));
  if (request.cpuSeconds !== undefined) argv.push("--cpu-seconds", String(request.cpuSeconds));
  if (request.maxProcesses !== undefined) {
    argv.push("--max-processes", String(request.maxProcesses));
  }
  if (request.secure === true) argv.push("--secure");
  if (request.policy !== undefined) argv.push("--policy", request.policy);
  for (const entry of request.proxyAllow ?? []) argv.push("--proxy-allow", entry);
  if (request.record !== undefined) argv.push("--record", request.record);
  argv.push("--");
  argv.push(...request.command);
  return argv;
}

/** Normalized request: every default spelled out, argument vector included. */
export function canonicalRequest(request: RunRequest): Json {
  return {
    command: [...request.command],
    cpu_seconds: request.cpuSeconds ?? null,
    max_processes: request.maxProcesses ?? null,
    memory_mib: request.memoryMib ?? null,
    policy: request.policy ?? null,
    proxy_allow: [...(request.proxyAllow ?? [])],
    record: request.record ?? null,
    rootfs: request.rootfs,
    secure: request.secure === true,
    timeout_ms: request.timeoutMs ?? DEFAULT_TIMEOUT_MS,
    workspace: request.workspace,
    argv: requestArgv(request),
  };
}

export function classify(exitCode: number, stderr: string): Outcome {
  if (exitCode === 124) return "timeout";
  if (exitCode === 126) return "exec_failed";
  if (exitCode === 125) {
    if (stderr.includes(POLICY_REJECTED_MARKER)) return "policy_rejected";
    if (stderr.includes(ENFORCEMENT_MARKER)) return "enforcement_unavailable";
    return "setup_failed";
  }
  return "exited";
}

/** Read a JSONL run record into memory, ignoring blank and partial lines. */
export function parseEvents(record?: string): Event[] {
  if (record === undefined || !existsSync(record)) return [];
  const events: Event[] = [];
  for (const line of readFileSync(record, "utf8").split("\n")) {
    const trimmed = line.trim();
    if (trimmed === "") continue;
    try {
      events.push(JSON.parse(trimmed) as Event);
    } catch {
      // The writer may be mid-line; the next read picks it up.
    }
  }
  return events;
}

const REPORT_KEYS = ["v", "kind", "generated_at_ms", "policy", "cases", "summary"];
const REPORT_POLICY_KEYS = ["path", "version", "fingerprint"];
const REPORT_CASE_KEYS = ["name", "expectation", "verdict", "exit_code", "duration_ms", "detail"];
const REPORT_VERDICTS = new Set(["pass", "fail", "pending"]);

function keysOf(value: unknown): string[] {
  if (typeof value !== "object" || value === null) return [];
  return Object.keys(value as Json).sort();
}

function sameKeys(value: unknown, expected: string[]): boolean {
  const actual = keysOf(value);
  const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
}

/** Check a report against docs/report.schema.json (same rules as the Python SDK). */
export function validateReport(report: unknown): void {
  if (!sameKeys(report, REPORT_KEYS)) {
    throw new ReportError(`report keys differ: ${JSON.stringify(keysOf(report))}`);
  }
  const typed = report as Json;
  if (typed.v !== 1) throw new ReportError(`unsupported report version ${String(typed.v)}`);
  if (typed.kind !== "easy-sandbox-verify-report") {
    throw new ReportError(`unexpected report kind ${String(typed.kind)}`);
  }
  if (!sameKeys(typed.policy, REPORT_POLICY_KEYS)) {
    throw new ReportError("report policy block has the wrong shape");
  }
  const policy = typed.policy as Json;
  if (typeof policy.version !== "number" || typeof policy.fingerprint !== "string") {
    throw new ReportError("report policy block has the wrong types");
  }
  const cases = typed.cases;
  if (!Array.isArray(cases) || cases.length === 0) {
    throw new ReportError("a report must contain at least one case");
  }
  for (const entry of cases) {
    if (typeof entry !== "object" || entry === null) throw new ReportError("case is not an object");
    const extra = keysOf(entry).filter((key) => !REPORT_CASE_KEYS.includes(key));
    if (extra.length > 0) throw new ReportError(`case has unexpected fields: ${extra.join(",")}`);
    const item = entry as Json;
    if (typeof item.name !== "string" || typeof item.detail !== "string") {
      throw new ReportError("case is missing a required field");
    }
    if (typeof item.duration_ms !== "number") throw new ReportError("case is missing a duration");
    if (!REPORT_VERDICTS.has(String(item.verdict))) {
      throw new ReportError(`unknown verdict ${String(item.verdict)}`);
    }
  }
  const summary = typed.summary as Json;
  if (!sameKeys(summary, ["total", "passed", "failed", "pending"])) {
    throw new ReportError("summary block has the wrong shape");
  }
  if (summary.total !== cases.length) throw new ReportError("summary total does not match");
  const counted =
    Number(summary.passed) + Number(summary.failed) + Number(summary.pending);
  if (counted !== Number(summary.total)) throw new ReportError("summary does not add up");
}

/** Drop volatile fields so two runs of the same cases compare equal. */
export function canonicalReport(report: unknown): Json {
  validateReport(report);
  const typed = report as Json;
  const cases = typed.cases as Json[];
  return {
    v: typed.v,
    kind: typed.kind,
    policy: {
      version: (typed.policy as Json).version,
      fingerprint: (typed.policy as Json).fingerprint,
    },
    cases: cases.map((entry) => ({
      name: entry.name,
      expectation: entry.expectation ?? null,
      verdict: entry.verdict,
      exit_code: entry.exit_code ?? null,
      detail: entry.detail,
    })),
    summary: { ...(typed.summary as Json) },
  };
}

export interface RunResult {
  outcome: Outcome;
  exitCode: number;
  request: RunRequest;
  stdout: string;
  stderr: string;
  recordPath?: string;
  events: Event[];
  rejected: boolean;
  canonical(): Json;
}

export interface VerifyResult {
  outcome: VerifyOutcome;
  exitCode: number;
  report?: Json;
  canonical(): Json;
}

export interface RunStream {
  events: AsyncGenerator<Event, void, void>;
  result: Promise<RunResult>;
}

function spawnLauncher(binary: string, argv: string[]): Spawned {
  const options: SpawnOptions = { stdio: ["ignore", "pipe", "pipe"] };
  let child: ChildProcess;
  try {
    child = spawn(binary, argv, options);
  } catch (error) {
    throw new SandboxError(`cannot start ${binary}: ${String(error)}`);
  }
  const collect = (stream: NodeJS.ReadableStream | null): Promise<string> =>
    new Promise((resolve, reject) => {
      if (stream === null) {
        resolve("");
        return;
      }
      let text = "";
      stream.setEncoding("utf8");
      stream.on("data", (chunk: string) => {
        text += chunk;
      });
      stream.on("end", () => resolve(text));
      stream.on("error", reject);
    });
  return { child, stdout: collect(child.stdout), stderr: collect(child.stderr) };
}

function exitCodeOf(child: ChildProcess): number {
  return child.exitCode === null ? 1 : child.exitCode;
}

function canonicalResult(
  outcome: Outcome,
  exitCode: number,
  request: RunRequest,
  events: Event[],
): Json {
  return {
    outcome,
    exit_code: exitCode,
    request: canonicalRequest(request),
    // Only the kinds, so two runs of the same request compare equal.
    events: events.map((event) => (typeof event.kind === "string" ? event.kind : "unknown")),
  };
}

export class Sandbox {
  binary: string;

  constructor(binary: string) {
    this.binary = binary;
  }

  /** Run to completion and classify the result. */
  async run(request: RunRequest): Promise<RunResult> {
    let temporaryDirectory: string | undefined;
    let effective = request;
    if (request.record === undefined) {
      // The record is always collected, so events are available even when the
      // caller did not ask for a file.  The canonical form keeps the caller's
      // request, so this internal path never leaks into it.
      temporaryDirectory = mkdtempSync(join(tmpdir(), "easysandbox-"));
      effective = { ...request, record: join(temporaryDirectory, "run.jsonl") };
    }
    let exitCode = 1;
    let stdout = "";
    let stderr = "";
    let events: Event[] = [];
    try {
      const spawned = spawnLauncher(this.binary, requestArgv(effective));
      [stdout, stderr] = await Promise.all([spawned.stdout, spawned.stderr]);
      await new Promise<void>((resolve) => {
        if (spawned.child.exitCode !== null) resolve();
        else spawned.child.on("close", () => resolve());
      });
      exitCode = exitCodeOf(spawned.child);
      events = parseEvents(effective.record);
    } finally {
      if (temporaryDirectory !== undefined) {
        rmSync(temporaryDirectory, { recursive: true, force: true });
      }
    }
    const outcome = classify(exitCode, stderr);
    return {
      outcome,
      exitCode,
      request,
      stdout,
      stderr,
      recordPath: request.record,
      events,
      rejected: outcome === "policy_rejected" || outcome === "enforcement_unavailable",
      canonical(): Json {
        return canonicalResult(outcome, exitCode, request, events);
      },
    };
  }

  /** Yield events while the run happens, then resolve the result. */
  stream(request: RunRequest, pollIntervalMs = 20): RunStream {
    const record = join(mkdtempSync(join(tmpdir(), "easysandbox-stream-")), "run.jsonl");
    writeFileSync(record, "");
    const effective: RunRequest = { ...request, record };
    const spawned = spawnLauncher(this.binary, requestArgv(effective));
    const collected: Event[] = [];

    const events = (async function* (): AsyncGenerator<Event, void, void> {
      for (;;) {
        for (const event of parseEvents(record).slice(collected.length)) {
          collected.push(event);
          yield event;
        }
        if (spawned.child.exitCode !== null) {
          for (const event of parseEvents(record).slice(collected.length)) {
            collected.push(event);
            yield event;
          }
          return;
        }
        await delay(pollIntervalMs);
      }
    })();

    const result = (async (): Promise<RunResult> => {
      for await (const _event of events) {
        // Draining is what drives the generator; the events themselves are
        // also collected for the result below.
      }
      const [stdout, stderr] = await Promise.all([spawned.stdout, spawned.stderr]);
      const exitCode = exitCodeOf(spawned.child);
      const outcome = classify(exitCode, stderr);
      rmSync(join(record, ".."), { recursive: true, force: true });
      return {
        outcome,
        exitCode,
        request,
        stdout,
        stderr,
        events: collected,
        rejected: outcome === "policy_rejected" || outcome === "enforcement_unavailable",
        canonical(): Json {
          return canonicalResult(outcome, exitCode, request, collected);
        },
      };
    })();

    return { events, result };
  }

  /** Run independent cases and return the validated report. */
  async verify(options: {
    policy: string;
    cases: string;
    rootfs: string;
    workspace: string;
    report?: string;
    records?: string;
    timeoutMs?: number;
  }): Promise<VerifyResult> {
    const directory = mkdtempSync(join(tmpdir(), "easysandbox-verify-"));
    const reportPath = options.report ?? join(directory, "report.json");
    const argv = [
      "verify",
      "--policy",
      options.policy,
      "--cases",
      options.cases,
      "--rootfs",
      options.rootfs,
      "--workspace",
      options.workspace,
      "--report",
      reportPath,
    ];
    if (options.records !== undefined) argv.push("--records", options.records);
    if (options.timeoutMs !== undefined) argv.push("--timeout-ms", String(options.timeoutMs));

    const spawned = spawnLauncher(this.binary, argv);
    const [, stderr] = await Promise.all([spawned.stdout, spawned.stderr]);
    await new Promise<void>((resolve) => {
      if (spawned.child.exitCode !== null) resolve();
      else spawned.child.on("close", () => resolve());
    });
    const exitCode = exitCodeOf(spawned.child);
    rmSync(directory, { recursive: true, force: true });

    let outcome: VerifyOutcome;
    if (exitCode === 125) {
      outcome = "rejected";
    } else if (exitCode === 0) {
      outcome = "all_passed";
    } else if (exitCode === 1) {
      outcome = "failed";
    } else {
      outcome = "pending";
    }

    let report: Json | undefined;
    if (outcome !== "rejected") {
      if (!existsSync(reportPath)) {
        throw new ReportError(`verify wrote no report; stderr=${stderr.slice(-300)}`);
      }
      report = JSON.parse(readFileSync(reportPath, "utf8")) as Json;
      validateReport(report);
    }
    return {
      outcome,
      exitCode,
      report,
      canonical(): Json {
        return {
          outcome,
          exit_code: exitCode,
          report: report === undefined ? null : canonicalReport(report),
        };
      },
    };
  }
}

/* ------------------------------------------------------------------ CLI ---- */
/* Used by the cross-SDK tests: the same spec in, the same JSON out. */

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (typeof value !== "object" || value === null) return value;
  const source = value as Json;
  const sorted: Json = {};
  for (const key of Object.keys(source).sort()) sorted[key] = sortKeys(source[key]);
  return sorted;
}

function print(value: unknown): void {
  process.stdout.write(`${JSON.stringify(sortKeys(value), null, 2)}\n`);
}

function requestFromSpec(spec: Json): RunRequest {
  return {
    rootfs: String(spec.rootfs),
    workspace: String(spec.workspace),
    command: (spec.command as string[]).map(String),
    policy: spec.policy === undefined || spec.policy === null ? undefined : String(spec.policy),
    timeoutMs: spec.timeout_ms === undefined ? DEFAULT_TIMEOUT_MS : Number(spec.timeout_ms),
    memoryMib: spec.memory_mib === undefined ? undefined : Number(spec.memory_mib),
    cpuSeconds: spec.cpu_seconds === undefined ? undefined : Number(spec.cpu_seconds),
    maxProcesses: spec.max_processes === undefined ? undefined : Number(spec.max_processes),
    secure: spec.secure === true,
    proxyAllow: ((spec.proxy_allow as string[]) ?? []).map(String),
    record: spec.record === undefined || spec.record === null ? undefined : String(spec.record),
  };
}

async function readSpec(): Promise<Json> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(chunk as Buffer);
  return JSON.parse(Buffer.concat(chunks).toString("utf8")) as Json;
}

async function main(): Promise<number> {
  const command = process.argv[2];
  const spec = await readSpec();
  const binary = String(spec.binary ?? process.env.EASY_SANDBOX_BIN ?? "easy-sandbox");
  const sandbox = new Sandbox(binary);

  if (command === "canonical") {
    print(canonicalRequest(requestFromSpec(spec)));
    return 0;
  }
  if (command === "run") {
    const result = await sandbox.run(requestFromSpec(spec));
    print(result.canonical());
    return 0;
  }
  if (command === "verify") {
    const verified = await sandbox.verify({
      policy: String(spec.policy),
      cases: String(spec.cases),
      rootfs: String(spec.rootfs),
      workspace: String(spec.workspace),
      report: spec.report === undefined || spec.report === null ? undefined : String(spec.report),
      records: spec.records === undefined || spec.records === null ? undefined : String(spec.records),
      timeoutMs: spec.timeout_ms === undefined ? undefined : Number(spec.timeout_ms),
    });
    print(verified.canonical());
    return 0;
  }
  process.stderr.write(`usage: easysandbox.ts <canonical|run|verify> < spec.json\n`);
  return 64;
}

const entry = process.argv[1];
if (entry !== undefined && import.meta.url === pathToFileURL(entry).href) {
  main()
    .then((code) => process.exit(code))
    .catch((error: unknown) => {
      process.stderr.write(`easysandbox: ${String(error)}\n`);
      process.exit(1);
    });
}
