#!/usr/bin/env node
import { compilePatterns, loadJevConfig } from './config.js';
import { startJevLogsServer } from './server.js';
import { createReadStream } from 'node:fs';
import { readFile, stat } from 'node:fs/promises';
import { createInterface } from 'node:readline';
import { createRequire } from 'node:module';
import { createJevLogs, createJevPager, errorSeverity, jevProvider, normalizeLogTemplate, redactCommonSecrets, scoreDecisions, type LogInput, type Evaluation, type Decision, type PageDecision, type JevStats, type PageStats, type ScoreRow } from './index.js';

const { version } = createRequire(import.meta.url)('../package.json') as { version: string };
const HELP = `
  jevlogs ${version} — keep your logs. spend on the signal.

  npx jevlogs                         Offline sample demo (no key, no network)
  npx jevlogs --live                  Start local OTLP HTTP receiver (JSON or protobuf)
  npx jevlogs --live --file app.log    Evaluate a text or JSONL log file
  cat app.log | npx jevlogs --live --stdin --json
  tail -f app.log | npx jevlogs --live --stdin --follow --json
  npx jevlogs --page                   Offline page/hold demo
  npx jevlogs --live --page --file app.log
  npx jevlogs --live --group --file incident.jsonl --baseline yesterday.jsonl

  --config <path>    Config file (default ./jevlogs.config.json)
  --page             Page or hold from one probability (sample, file, or stdin)
  --page-above <n>   Page when probability is at least n (0.05–0.95, default 0.5)
  --suppress-ms <n>  Hold repeat pages of one template for n milliseconds (requires --page)
  --max-calls <n>    Stop after n model calls; later records stay conservative
  --labels           Score important/label fields and print recall and precision
  --sample           Evaluate built-in samples with --live and exit
  --port <number>    Local receiver port (default 4318)
  --demo             Explicit offline sample demo (default)
  --live             Send redacted log bodies to Jev via OpenRouter or Vercel AI Gateway
  --file <path>      Read a local text or JSONL file (requires --live or --group)
  --stdin            Read stdin (requires --live or --group; finish input to begin)
  --follow           With --stdin: evaluate each line as it arrives, no limit
  --limit <1–100>    Max records to evaluate; default 20 (ignored with --follow or --group)
  --group            Collapse repeated templates, one Jev call per template (--file or --stdin,
                     no 1 MiB limit, works offline without --live). Rows are ranked: protected,
                     grown vs baseline (by growth), Jev value, count. Default --max-calls 100
  --baseline <path>  With --group: count the same templates in an earlier window of equal length
  --json             Emit one JSON object per record; summary goes to stderr
  --help, -h         Show help
  --version, -v      Show version

  Live mode requires OPENROUTER_API_KEY or AI_GATEWAY_API_KEY in your server environment.
  OpenRouter is used when both are set. OPENROUTER_JEV_MODEL overrides typesafe/jev-1.13.
  Provider charges apply. Default redaction is not a complete PII policy.
  Input limit: 1 MiB total / 8,000 characters per record (--group: no total limit). No files are changed.
  --group config: groupMask [{ match, flags }] masks free text as <*>; groupKeep keeps metric lines unmerged.
  JSONL accepts body, message, or msg, severityNumber, severityText or level,
  and protected: true. Pino levels 10–60 map to OpenTelemetry severity.
  Errors and protected logs bypass analysis. --page still asks the model about ERROR lines.
  FATAL, CRITICAL, and protected logs page without a model call.
  Receiver: GET /health, GET /stats. POST /v1/logs accepts JSON or protobuf; gRPC is not supported.
  Set forwardUrl in the config to send annotated records on to your collector.
`;
const MAX_BYTES = 1024 * 1024;
/** Model calls in flight for --follow, --file, and --group. */
const CONCURRENCY = 4;
const samples: LogInput[] = [
  { body: 'GET /health returned 200 in 2ms', severityText: 'INFO' },
  { body: 'Cache hit for product:482', severityText: 'DEBUG' },
  { body: 'Payment capture failed after three retries', severityText: 'ERROR' },
  { body: 'Database connection pool at 94% capacity for five minutes', severityText: 'WARN' },
];
// Fixed sample answers demonstrate the SDK policy. They are not model inference.
const sampleAnswers: Evaluation[] = [
  { value: 0, priority: 'low', actionableProbability: 0.01 },
  { value: 25, priority: 'low', actionableProbability: 0.03 },
  { value: 100, priority: 'critical', actionableProbability: 0.99 },
  { value: 75, priority: 'high', actionableProbability: 0.92 },
];
const PINO_LEVELS: Record<number, { text: string; severityNumber: number }> = {
  10: { text: 'TRACE', severityNumber: 1 }, 20: { text: 'DEBUG', severityNumber: 5 }, 30: { text: 'INFO', severityNumber: 9 },
  40: { text: 'WARN', severityNumber: 13 }, 50: { text: 'ERROR', severityNumber: 17 }, 60: { text: 'FATAL', severityNumber: 21 },
};
const POSITIVE_LABELS = new Set(['incident', 'page', 'analyze', 'important', 'signal', 'true', 'yes']);
const NEGATIVE_LABELS = new Set(['noise', 'ignore', 'retain', 'ok', 'normal', 'false', 'no', 'background']);
interface ParsedRecord { input: LogInput; important?: boolean; time?: string | number }
function parseRecord(line: string, index: number, strictLabels: boolean, maxChars = 8000): ParsedRecord {
  const labeled = (input: LogInput, source?: Record<string, unknown>): ParsedRecord => {
    if (!source) return { input };
    if (source.important !== undefined && typeof source.important !== 'boolean') throw new Error(`Line ${index + 1}: important must be a boolean.`);
    if (typeof source.important === 'boolean') return { input, important: source.important };
    const label = source.label;
    if (typeof label === 'boolean') return { input, important: label };
    if (typeof label === 'string') {
      const word = label.toLowerCase();
      if (POSITIVE_LABELS.has(word)) return { input, important: true };
      if (NEGATIVE_LABELS.has(word)) return { input, important: false };
      if (strictLabels) throw new Error(`Line ${index + 1}: label "${label}" is not a known word.`);
    } else if (label !== undefined && strictLabels) throw new Error(`Line ${index + 1}: label must be a boolean or string.`);
    return { input };
  };
  if (line.length > maxChars) throw new Error(`Line ${index + 1} exceeds ${maxChars.toLocaleString('en-US')} characters.`);
  let record: unknown;
  try { record = JSON.parse(line); } catch {
    const time = line.match(/\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?/)?.[0];
    return { ...labeled({ body: line, severityText: line.match(/\b(ERROR|FATAL|CRITICAL|WARN|INFO|DEBUG|TRACE)\b/i)?.[1]?.toUpperCase() }), ...(time ? { time } : {}) };
  }
  if (record && typeof record === 'object' && !Array.isArray(record)) {
    const r = record as Record<string, unknown>;
    if (r.severityNumber !== undefined && (typeof r.severityNumber !== 'number' || !Number.isFinite(r.severityNumber))) throw new Error(`Line ${index + 1}: severityNumber must be numeric.`);
    const level = r.severityText ?? r.level;
    let severityText = typeof level === 'string' ? level.toUpperCase() : undefined;
    let severityNumber = r.severityNumber as number | undefined;
    if (severityText === undefined && typeof level === 'number' && Number.isInteger(level) && PINO_LEVELS[level]) {
      severityText = PINO_LEVELS[level].text;
      severityNumber ??= PINO_LEVELS[level].severityNumber;
    }
    const service = typeof r.service === 'string' ? r.service : undefined;
    const time = [r.timestamp, r.time, r['@timestamp'], r.ts, r.timeUnixNano].find(value => typeof value === 'string' || typeof value === 'number') as string | number | undefined;
    return { ...labeled({ body: r.body ?? r.message ?? r.msg ?? record, severityNumber, severityText, protected: r.protected === true, ...(service ? { service } : {}) }, r), ...(time === undefined ? {} : { time }) };
  }
  return labeled({ body: record });
}
async function stdinText(): Promise<string> {
  const chunks: Buffer[] = []; let bytes = 0;
  for await (const chunk of process.stdin) {
    const buffer = Buffer.from(chunk); bytes += buffer.length;
    if (bytes > MAX_BYTES) { process.stdin.destroy(); throw new Error('Input exceeds 1 MiB. Pass a smaller file.'); }
    chunks.push(buffer);
  }
  return Buffer.concat(chunks).toString('utf8');
}
function display(body: unknown): string {
  const text = typeof body === 'string' ? body : JSON.stringify(body);
  return redactCommonSecrets(text ?? '').replace(/[\x00-\x1f\x7f-\x9f]/g, ' ').slice(0, 110);
}
function printDecision(index: number, mode: 'live' | 'demo', record: LogInput, decision: Decision, json: boolean, important?: boolean) {
  if (json) { console.log(JSON.stringify({ line: index + 1, mode, ...(important === undefined ? {} : { important }), ...decision })); return; }
  const tags = [decision.reason + (decision.rule ? ` ${decision.rule}` : ''), decision.cached ? 'cached' : '', decision.actionableProbability === null ? '' : `actionable ${(decision.actionableProbability * 100).toFixed(0)}%`].filter(Boolean).join(' · ');
  console.log(`  ${String(Math.round(decision.value)).padStart(3)} / 100  ${decision.priority.padEnd(8)} ${decision.route === 'analyze' ? 'ANALYZE' : 'RETAIN '}  ${display(record.body)}\n             ${tags}\n`);
}
function printPage(index: number, mode: 'live' | 'demo', record: LogInput, decision: PageDecision, json: boolean, important?: boolean) {
  if (json) { console.log(JSON.stringify({ line: index + 1, mode, task: 'page', ...(important === undefined ? {} : { important }), ...decision })); return; }
  const tags = [decision.reason + (decision.rule ? ` ${decision.rule}` : ''), decision.cached ? 'cached' : '', decision.probability === null ? '' : `p ${(decision.probability * 100).toFixed(0)}%`].filter(Boolean).join(' · ');
  console.log(`  ${decision.page ? 'PAGE' : 'HOLD'}  ${display(record.body)}\n             ${tags}\n`);
}
function pageSummary(stats: PageStats, live: boolean): string {
  const parts = [`${stats.decisions} logs checked`, `${stats.page} would page`, `${stats.hold} held`];
  if (live) {
    if (stats.cached) parts.push(`${stats.cached} served from cache`);
    if (stats.rules) parts.push(`${stats.rules} decided by rules`);
    if (stats.modelLatencyMs.count) parts.push(`${stats.modelLatencyMs.count} Jev calls, avg ${(stats.modelLatencyMs.total / stats.modelLatencyMs.count).toFixed(0)} ms`);
    if (stats.inputTokens) parts.push(`${stats.inputTokens} Jev input tokens`);
  }
  if (stats.suppressed) parts.push(`${stats.suppressed} repeat pages held`);
  if (stats.budget) parts.push(`${stats.budget} held by the model-call budget`);
  return parts.join(' · ') + '.';
}
function summary(stats: JevStats, live: boolean): string {
  const parts = [`${stats.decisions} logs preserved`, `${stats.analyze} selected for analysis`, `${stats.retain} may skip deeper analysis`];
  if (live) {
    if (stats.cached) parts.push(`${stats.cached} served from cache`);
    if (stats.rules) parts.push(`${stats.rules} decided by rules`);
    if (stats.modelLatencyMs.count) parts.push(`${stats.modelLatencyMs.count} Jev calls, avg ${(stats.modelLatencyMs.total / stats.modelLatencyMs.count).toFixed(0)} ms`);
    if (stats.inputTokens) parts.push(`${stats.inputTokens} Jev input tokens`);
  }
  if (stats.budget) parts.push(`${stats.budget} kept by the model-call budget`);
  return parts.join(' · ') + '.';
}
function formatScore(report: ReturnType<typeof scoreDecisions>, paging: boolean): string {
  const recall = report.recall === null ? 'n/a' : `${(report.recall * 100).toFixed(0)}% (${report.truePositives}/${report.important})`;
  const precision = report.precision === null ? 'n/a' : `${(report.precision * 100).toFixed(0)}% (${report.truePositives}/${report.selected})`;
  const noun = paging ? 'page' : 'analysis';
  const misses = report.misses.length ? ` Misses: ${report.misses.map(line => `line ${line}`).join(', ')}.` : '';
  return `Labels: ${noun} recall ${recall} · precision ${precision} · ${report.falsePositives} false positives.${misses}`;
}
/** Run fn over items with at most `limit` in flight; results keep input order. */
async function pool<T, R>(items: T[], limit: number, fn: (item: T, index: number) => Promise<R>): Promise<R[]> {
  const results = new Array<R>(items.length);
  let next = 0;
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) { const i = next++; results[i] = await fn(items[i]!, i); }
  }));
  return results;
}
/** masks must be global regexes. Coarser than the cache key on purpose: every number becomes N, so counters and durations collapse into one template. */
function groupTemplate(text: string, masks: RegExp[]): string {
  const masked = masks.reduce((t, mask) => t.replace(mask, '<*>'), redactCommonSecrets(text));
  return normalizeLogTemplate(masked).replace(/\d+(?:\.\d+)?/g, 'N');
}
interface Group { key: string; input: LogInput; template: string; count: number; line: number; lastLine: number; first?: string | number; last?: string | number; keep: boolean; baseline?: number; growth?: number }
/** Stream records into templates. Line numbers are physical file lines, so `sed -n <line>p` finds the example. */
async function readGroups(input: NodeJS.ReadableStream, masks: RegExp[], keep: RegExp[]) {
  const groups = new Map<string, Group>();
  let lines = 0, records = 0, skipped = 0;
  for await (const line of createInterface({ input, crlfDelay: Infinity })) {
    const index = lines++;
    if (!line.trim()) continue;
    let parsed: ParsedRecord;
    try { parsed = parseRecord(line, index, false, MAX_BYTES); } catch (error) { skipped++; console.error(`jevlogs: skipped line ${index + 1}: ${error instanceof Error ? error.message : 'invalid record'}`); continue; }
    records++;
    const { input: record, time } = parsed;
    const text = typeof record.body === 'string' ? record.body : JSON.stringify(record.body) ?? '';
    const kept = keep.some(rule => rule.test(text));
    const template = kept ? redactCommonSecrets(text) : groupTemplate(text, masks);
    const key = kept ? `line:${index}` : `${record.severityText ?? record.severityNumber ?? ''}\n${record.service ?? ''}\n${template}`;
    const group = groups.get(key);
    if (group) { group.count++; group.lastLine = index + 1; group.last = time ?? group.last; if (record.protected) group.input.protected = true; }
    else groups.set(key, { key, input: record, template, count: 1, line: index + 1, lastLine: index + 1, first: time, last: time, keep: kept });
  }
  return { groups, records, skipped };
}
// ponytail: growth >= 2 is a fixed cut for "grew or appeared"; tune it on labeled incidents.
const grown = (group: Group): boolean => (group.growth ?? 0) >= 2;
function rankGroups(a: { group: Group; decision?: Decision }, b: { group: Group; decision?: Decision }): number {
  // Offline there is no decision, so severity alone ranks protected records first, as triage would.
  // Among grown templates the size of the jump ranks first: on a real incident a x361 proxy timeout sat below one-off lines on Jev value alone.
  const key = ({ group, decision }: typeof a) => [group.input.protected || errorSeverity(group.input) ? 0 : 1, decision?.route === 'retain' ? 1 : 0, grown(group) ? 0 : 1, grown(group) ? -group.growth! : 0, -(decision?.value ?? 0), -group.count];
  const x = key(a), y = key(b);
  for (let i = 0; i < x.length; i++) if (x[i] !== y[i]) return x[i]! - y[i]!;
  return 0;
}
function printGroup(group: Group, decision: Decision | undefined, json: boolean) {
  const level = group.input.severityText ?? group.input.severityNumber;
  const time = group.first === undefined ? {} : { first: group.first, last: group.last };
  const base = group.baseline === undefined ? {} : { baseline: group.baseline, growth: group.growth };
  if (json) { console.log(JSON.stringify({ line: group.line, lastLine: group.lastLine, count: group.count, ...(level === undefined ? {} : { level }), ...time, ...base, ...(group.keep ? { keep: true } : {}), template: group.template.slice(0, 1000), ...decision })); return; }
  const tags = [
    level === undefined ? '' : String(level), decision ? decision.reason + (decision.rule ? ` ${decision.rule}` : '') : '', decision?.cached ? 'cached' : '',
    decision?.actionableProbability == null ? '' : `actionable ${(decision.actionableProbability * 100).toFixed(0)}%`,
    group.baseline === undefined ? '' : `baseline ${group.baseline} (×${group.growth})`,
    group.count > 1 ? `lines ${group.line}–${group.lastLine}` : `line ${group.line}`,
  ].filter(Boolean).join(' · ');
  const head = decision ? `${String(Math.round(decision.value)).padStart(3)} / 100  ${decision.priority.padEnd(8)} ${decision.route === 'analyze' ? 'ANALYZE' : 'RETAIN '}  ` : '';
  console.log(`  ${String(group.count).padStart(6)}×  ${head}${display(group.template)}\n           ${tags}\n`);
}
async function main() {
  const args = process.argv.slice(2);
  let sample = false, port: number | undefined, configPath: string | undefined;
  let live = false, demo = false, json = false, stdin = false, follow = false, page = false, labels = false, group = false, baseline: string | undefined, file: string | undefined, limit = 20, pageAbove: number | undefined, maxCalls: number | undefined, suppressMs: number | undefined;
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--help' || arg === '-h') { console.log(HELP); return; }
    if (arg === '--version' || arg === '-v') { console.log(version); return; }
    if (arg === '--live') live = true;
    else if (arg === '--sample') sample = true;
    else if (arg === '--demo') demo = true;
    else if (arg === '--json') json = true;
    else if (arg === '--stdin') stdin = true;
    else if (arg === '--follow') follow = true;
    else if (arg === '--page') page = true;
    else if (arg === '--labels') labels = true;
    else if (arg === '--group') group = true;
    else if (arg === '--file' || arg === '--limit' || arg === '--port' || arg === '--config' || arg === '--page-above' || arg === '--max-calls' || arg === '--suppress-ms' || arg === '--baseline') {
      const value = args[++i];
      if (!value || value.startsWith('--')) throw new Error(`${arg} requires a value.`);
      if (arg === '--config') configPath = value;
      else if (arg === '--file') file = value;
      else if (arg === '--baseline') baseline = value;
      else if (arg === '--port') { port = Number(value); if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Invalid port'); }
      else if (arg === '--page-above') { pageAbove = Number(value); if (!Number.isFinite(pageAbove) || pageAbove < 0.05 || pageAbove > 0.95) throw new Error('--page-above must be a number from 0.05 to 0.95.'); }
      else if (arg === '--max-calls') { maxCalls = Number(value); if (!Number.isInteger(maxCalls) || maxCalls < 0 || maxCalls > 1_000_000) throw new Error('--max-calls must be an integer from 0 to 1000000.'); }
      else if (arg === '--suppress-ms') { suppressMs = Number(value); if (!Number.isInteger(suppressMs) || suppressMs < 0 || suppressMs > 86_400_000) throw new Error('--suppress-ms must be an integer from 0 through 86400000.'); }
      else { limit = Number(value); if (!Number.isInteger(limit) || limit < 1 || limit > 100) throw new Error('--limit must be an integer from 1 to 100.'); }
    } else throw new Error(`Unknown option: ${arg}. Run jevlogs --help.`);
  }
  if (live && demo) throw new Error('Choose --live or --demo, not both.');
  if (file && stdin) throw new Error('Choose --file or --stdin, not both.');
  if ((file || stdin) && !live && !group) throw new Error('Custom logs require --live or --group. The offline demo uses fixed samples only.');
  if (group && !file && !stdin) throw new Error('--group requires --file or --stdin.');
  if (group && (follow || page || labels || sample)) throw new Error('--group ranks a finished file or stdin for investigation; it does not combine with --follow, --page, --labels, or --sample.');
  if (baseline && !group) throw new Error('--baseline requires --group.');
  if (follow && !stdin) throw new Error('--follow requires --stdin.');
  if (pageAbove !== undefined && !page) throw new Error('--page-above requires --page.');
  if (suppressMs !== undefined && !page) throw new Error('--suppress-ms requires --page.');
  if (page && !sample && !file && !stdin && live) throw new Error('--page evaluates a sample, file, or stdin stream. The OTLP receiver still scores analysis routes.');
  if (labels && live && !sample && !file && !stdin) throw new Error('--labels scores a sample, file, or stdin stream.');
  const config = live || group ? await loadJevConfig(configPath) : {};
  if (live && !jevProvider()) throw new Error('Live mode requires OPENROUTER_API_KEY or AI_GATEWAY_API_KEY. Set it in your environment; do not pass keys on the command line.');
  const via = jevProvider() === 'openrouter' ? 'OpenRouter' : 'Vercel AI Gateway';
  if (sample && (!live || file || stdin)) throw new Error('--sample requires --live without --file or --stdin');
  if (live && !sample && !file && !stdin) {
    const receiver = await startJevLogsServer({ ...config, maxModelCalls: maxCalls ?? config.maxModelCalls, port: port ?? config.port, onLog(event) {
      // CLI emits decisions and correlation IDs only, never raw bodies or credentials.
      console.log(JSON.stringify({ traceId: event.logRecord.traceId, spanId: event.logRecord.spanId, timeUnixNano: event.logRecord.timeUnixNano, ...event.decision }));
    } });
    const forwardNote = receiver.forwardUrl ? `Annotated records are forwarded to ${receiver.forwardUrl} (${config.forwardMode ?? 'annotate'}).` : 'No forwardUrl configured: decisions go to stdout only.';
    console.error(`JEV LOGS ${version} · LIVE receiver: ${receiver.url}\nSend OTLP HTTP logs (JSON or protobuf). gRPC is not supported. ${forwardNote}\nRedacted bodies go to ${via} / TypeSafe. Provider charges apply. GET /stats for counters. Ctrl+C to stop.`);
    const stop = () => {
      const s = receiver.stats();
      console.error(`\n${summary(s.triage, true)} ${s.forwarded ? `${s.forwarded} forwarded, ${s.forwardFailures} forward failures.` : ''}`.trimEnd());
      void receiver.close().catch(() => { process.exitCode = 1; });
    };
    process.once('SIGINT', stop); process.once('SIGTERM', stop);
    return;
  }
  const mode = live ? 'live' : 'demo';
  console.error(group && !live
    ? `\nJEV LOGS ${version} · GROUP · offline\nTemplates and counts only. No model calls, no network requests.\n`
    : page
    ? (live
      ? `\nJEV LOGS ${version} · LIVE PAGE · Jev via ${via}\nOne boolean question per log. Page when probability is at least ${pageAbove ?? 0.5}. Provider charges apply.\n`
      : `\nJEV LOGS ${version} · OFFLINE PAGE DEMO\nFixed sample probabilities, not Jev inference. No network requests.\n`)
    : (live
      ? `\nJEV LOGS ${version} · LIVE · Jev via ${via}\nRedacted bodies are sent to ${via} / TypeSafe; provider charges apply.\n`
      : `\nJEV LOGS ${version} · OFFLINE DEMO\nFixed sample answers, not Jev inference. No network requests. Try --live with an OpenRouter or Gateway key.\n`));
  let demoIndex = 0;
  const shared = { timeoutMs: config.timeoutMs, maxInputChars: config.maxInputChars, rules: config.rules, cache: live ? config.cache : false as const, normalizeTemplates: config.normalizeTemplates, maxModelCalls: maxCalls ?? config.maxModelCalls ?? (group ? 100 : undefined) };
  const jev = page
    ? createJevPager({ ...shared, suppressForMs: suppressMs ?? config.suppressForMs, ...(pageAbove === undefined ? {} : { pageAbove }), ...(live ? {} : { evaluator: async () => ({ probability: sampleAnswers[demoIndex % sampleAnswers.length]!.actionableProbability }) }) })
    : createJevLogs({ ...shared, retainBelow: config.retainBelow, ...(live ? {} : { evaluator: async () => sampleAnswers[demoIndex % sampleAnswers.length]! }) });
  const scored: ScoreRow[] = [];
  const finish = () => {
    const stats = jev.stats();
    const unavailable = stats.unavailable;
    console.error(page ? pageSummary(stats as PageStats, live) : summary(stats as JevStats, live));
    if (labels) {
      if (!scored.length) { console.error('jevlogs: no labeled records. Set important to true or false, or set label.'); process.exitCode = 1; return; }
      const report = scoreDecisions(scored);
      console.error(formatScore(report, page));
      if (report.falseNegatives) process.exitCode = 2;
    }
    if (unavailable) {
      console.error(page
        ? `${unavailable} evaluation(s) unavailable; those lines were held. Check ${via} access, connectivity, or input size.`
        : `${unavailable} evaluation(s) unavailable; records conservatively kept for analysis. Check ${via} access, connectivity, or input size.`);
      process.exitCode = 2;
    }
  };
  const triage = (record: LogInput) => (jev as ReturnType<typeof createJevLogs>).triage(record);
  const decide = (record: LogInput): Promise<Decision | PageDecision> => page ? (jev as ReturnType<typeof createJevPager>).decide(record) : triage(record);
  const show = (index: number, parsed: ParsedRecord, decision: Decision | PageDecision) => {
    const record = parsed.input;
    if (page) {
      const paged = decision as PageDecision;
      if (parsed.important !== undefined) scored.push({ important: parsed.important, selected: paged.page, line: index + 1 });
      printPage(index, mode, record, paged, json, parsed.important);
    } else {
      const routed = decision as Decision;
      if (parsed.important !== undefined) scored.push({ important: parsed.important, selected: routed.route === 'analyze', line: index + 1 });
      printDecision(index, mode, record, routed, json, parsed.important);
    }
  };
  const emit = async (index: number, parsed: ParsedRecord) => show(index, parsed, await decide(parsed.input));
  if (group) {
    const masks = compilePatterns(config.groupMask, 'groupMask').map(mask => new RegExp(mask.source, mask.flags + 'g'));
    const keep = compilePatterns(config.groupKeep, 'groupKeep');
    for (const path of [file, baseline]) if (path) await stat(path);
    const current = await readGroups(file ? createReadStream(file) : process.stdin, masks, keep);
    if (!current.groups.size) throw new Error('No log records found.');
    const groups = [...current.groups.values()];
    let note = '';
    if (baseline) {
      const base = await readGroups(createReadStream(baseline), masks, keep);
      for (const g of groups) if (!g.keep) { g.baseline = base.groups.get(g.key)?.count ?? 0; g.growth = Math.round((g.count + 1) / (g.baseline + 1) * 100) / 100; }
      note = ` · baseline ${base.records} records, ${groups.filter(grown).length} templates grew or appeared`;
    }
    // Grown templates claim the model-call budget first.
    groups.sort((a, b) => Number(grown(b)) - Number(grown(a)));
    const decisions = live ? await pool(groups, CONCURRENCY, g => triage(g.input)) : [];
    groups.map((g, i) => ({ group: g, decision: decisions[i] })).sort(rankGroups).forEach(row => printGroup(row.group, row.decision, json));
    console.error(`${current.records} records → ${groups.length} templates${current.skipped ? ` (${current.skipped} lines skipped)` : ''}${note}.`);
    if (live) finish();
    return;
  }
  if (follow) {
    // Streaming mode: bounded concurrency with readline backpressure; output order follows completion.
    const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });
    let index = 0, active = 0, closed = false;
    const pending = new Set<Promise<void>>();
    await new Promise<void>(resolve => {
      const maybeDone = () => { if (closed && active === 0) resolve(); };
      rl.on('line', line => {
        if (!line.trim()) return;
        const current = index++;
        let record: ParsedRecord;
        try { record = parseRecord(line, current, labels); } catch (error) { console.error(`jevlogs: skipped line ${current + 1}: ${error instanceof Error ? error.message : 'invalid record'}`); return; }
        active++;
        if (active >= CONCURRENCY) rl.pause();
        const task = emit(current, record).finally(() => { active--; pending.delete(task); if (active < CONCURRENCY) rl.resume(); maybeDone(); });
        pending.add(task);
      });
      rl.once('close', () => { closed = true; maybeDone(); });
    });
    finish();
    return;
  }
  let records: ParsedRecord[] = samples.map(input => ({ input }));
  if (file || stdin) {
    if (file && (await stat(file)).size > MAX_BYTES) throw new Error('Input exceeds 1 MiB. Pass a smaller file.');
    const text = file ? await readFile(file, 'utf8') : await stdinText();
    if (Buffer.byteLength(text) > MAX_BYTES) throw new Error('Input exceeds 1 MiB.');
    const lines = text.split(/\r?\n/).filter(line => line.trim());
    if (!lines.length) throw new Error('No log records found.');
    if (lines.length > limit) console.error(`Processing the first ${limit} of ${lines.length} records; raise --limit up to 100 to include more.`);
    records = lines.slice(0, limit).map((line, index) => parseRecord(line, index, labels));
  } else records = samples.slice(0, limit).map(input => ({ input }));
  // The demo evaluator reads demoIndex, so the offline demo runs one record at a time.
  const decisions = await pool(records, live ? CONCURRENCY : 1, (record, i) => { demoIndex = i; return decide(record.input); });
  decisions.forEach((decision, i) => show(i, records[i]!, decision));
  finish();
}
main().catch(error => { console.error(`jevlogs: ${error instanceof Error ? error.message : 'Unexpected failure'}`); process.exitCode = 1; });
