/**
 * Z3 certification of db-pending/0277 (CONTRACT). Replays db/ on PGlite, applies 0277, reads the
 * catalog and runs the formal RLS verifier (every rout_app policy is encoded to SMT; "proven" means
 * Z3 returned unsat for "a row of tenant B is visible/writable for tenant A").
 * Certified = no finding outside KNOWN_OPEN, every finding 0277 must close (F1, F2, F8b...) gone,
 * and only the reviewed PENDING_0277_DECLASSIFIED public profile columns are declassified.
 *
 *   bun scripts/formal-rls/certify-0277.ts [--smt-out dir]
 * Writes docs/rls-0277-certification.md. Read-only on Neon: it never connects to it.
 */
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { readCatalog } from "../schema-catalog";
import { Verifier } from "../formal-rls-verifier";
import { existsSync } from "node:fs";
import { CLOSED_BY_0277, KNOWN_OPEN } from "./tenant-model";
import { applyPending, replayDb, ROOT } from "./replay";

const args = process.argv.slice(2);
const smtOut = args.includes("--smt-out") ? args[args.indexOf("--smt-out") + 1] : undefined;

const db = await replayDb();
// Since its release 0277 is part of the db/ replay; before that it was applied from db-pending/.
if (!existsSync(join(ROOT, "db", "0277_tenant_contract_and_merge_fix.sql"))) await applyPending(db, "0277_tenant_contract_and_merge_fix.sql");
const cat = await readCatalog(async (q) => (await db.query<Record<string, unknown>>(q)).rows);
const opts = (await db.query<{ k: string; o: string[] | null }>(`select n.nspname || '.' || c.relname as k, c.reloptions as o from pg_class c join pg_namespace n on n.oid = c.relnamespace where c.relkind = 'v'`)).rows;
const report = await new Verifier(cat, Object.fromEntries(opts.map((r) => [r.k, r.o ?? []]))).run({ smtOut });
await db.close();

const mustClose = CLOSED_BY_0277.map((k) => k.id);
const open = new Set(KNOWN_OPEN.map((k) => k.id));
const fresh = report.findings.filter((f) => !open.has(f.id));
const stillOpen = report.findings.filter((f) => mustClose.includes(f.id));
const count = (s: string) => report.obligations.filter((o) => o.outcome.status === s).length;
const certified = fresh.length === 0 && stillOpen.length === 0 && count("unproven") === 0 && report.unusedModelEntries.length === 0;

const md = [
  "# Z3 certification — db-pending/0277_tenant_contract_and_merge_fix.sql",
  "",
  `Run: ${new Date().toISOString()} · offline PGlite replay of db/ (0277 included) · Neon not contacted`,
  "",
  `- Obligations: ${report.obligations.length}, Z3 checks: ${report.smtChecks}`,
  `- proven (unsat): ${count("proven")} · declassified (reviewed): ${count("declassified")} · service boundary: ${count("service_boundary")} · unproven: ${count("unproven")}`,
  `- SECURITY DEFINER without pg_catalog, pg_temp: ${report.searchPath.findings.length} of ${report.searchPath.definers}`,
  `- New findings: ${fresh.length} · findings 0277 must close still open: ${stillOpen.length} · unused model entries: ${report.unusedModelEntries.length}`,
  "",
  `**Result: ${certified ? "CERTIFIED" : "NOT CERTIFIED"}**`,
  "",
  ...[...fresh, ...stillOpen].map((f) => `- ${f.id}: ${f.detail}`),
  "",
  "Certification is a precondition for 0277, not a GO: 0277 stays in db-pending/ until production reports",
  "schema >= 0276, `scripts/tenant-backfill.ts` reports 0 deviations and the owner gives a separate GO.",
];
writeFileSync(join(ROOT, "docs", "rls-0277-certification.md"), md.join("\n") + "\n");
console.log(md.slice(4, 11).join("\n"));
process.exitCode = certified ? 0 : 1;
