/**
 * Tenant pre-flight and backfill for the 0276 -> 0277 transition.
 *
 * 0276 adds no new tenant column; its guards refuse rows that name a workspace the writer does not
 * belong to. Before 0277 (CONTRACT) may be applied, existing data must already satisfy what those
 * guards enforce, and the one data change 0277 makes (dropping the stored address of pending
 * handle invites) must be a no-op. This script measures both:
 *
 *   D1  rows whose workspace column names a workspace that does not exist
 *   D2  rows (identity + workspace column) whose identity is not a member of that workspace
 *   D3  workspaces.legacy_user_id that is not a member of the workspace
 *   B1  pending invites with invited_user_id whose stored e-mail equals that member's address
 *
 *   bun scripts/tenant-backfill.ts                       # dry run on an offline PGlite replay of db/
 *   bun scripts/tenant-backfill.ts --url-env OWNER_DATABASE_URL            # read-only report
 *   bun scripts/tenant-backfill.ts --url-env OWNER_DATABASE_URL --apply    # B1 in batches of 500
 *   bun scripts/tenant-backfill.ts --gateway             # read-only report through the agent's Neon connector
 *
 * Idempotent: --apply only nulls B1 addresses (same predicate as 0277) and re-running finds 0.
 * D1-D3 are never "fixed" automatically: a deviation there is a human decision. Exit 1 if any
 * count is non-zero after the run. The default run never connects to Neon.
 */
import { tenantColumns, loadSnapshot } from "./formal-rls-verifier";

type Q = (sql: string, params?: unknown[]) => Promise<Record<string, unknown>[]>;
const args = process.argv.slice(2);
const urlEnv = args.includes("--url-env") ? args[args.indexOf("--url-env") + 1] : undefined;
const apply = args.includes("--apply");
const gateway = args.includes("--gateway");
/** Only SELECT statements may go through the gateway mode. */
const READ_ONLY = /^\s*(with|select)\b/i;
const BATCH = 500;
const id = (s: string) => `"${s.replace(/"/g, '""')}"`;

const B1 = `from public.workspace_invites i where i.status = 'pending' and i.invited_user_id is not null and i.email is not null
  and exists (select 1 from public.users u where u.id = i.invited_user_id and pg_catalog.lower(u.email) = pg_catalog.lower(i.email))`;

export async function checks(q: Q) {
  const out: { check: string; count: number }[] = [];
  const cat = loadSnapshot();
  for (const t of cat.tables.filter((x) => x.schema === "public" && x.name !== "workspaces" && x.name !== "workspace_members")) {
    const { identity, workspace } = tenantColumns(t);
    for (const w of workspace) {
      const tbl = `public.${id(t.name)}`;
      const [r] = await q(`select count(*)::int as n from ${tbl} x where x.${id(w)} is not null and not exists (select 1 from public.workspaces s where s.id = x.${id(w)})`);
      out.push({ check: `D1 ${t.name}.${w}`, count: Number(r!.n) });
      // auth_user_id lives in the Better Auth id space, not public.users ids, so it is never a
      // workspace_members.user_id; comparing it would report every converted account.
      for (const u of identity.filter((c) => c !== "auth_user_id" && (c !== "id" || t.name === "profiles" || t.name === "users"))) {
        const [m] = await q(`select count(*)::int as n from ${tbl} x where x.${id(w)} is not null and x.${id(u)} is not null and not exists (select 1 from public.workspace_members m where m.workspace_id = x.${id(w)} and m.user_id = x.${id(u)})`);
        out.push({ check: `D2 ${t.name}.${u}->${w}`, count: Number(m!.n) });
      }
    }
  }
  const [d3] = await q(`select count(*)::int as n from public.workspaces s where s.legacy_user_id is not null and not exists (select 1 from public.workspace_members m where m.workspace_id = s.id and m.user_id = s.legacy_user_id)`);
  out.push({ check: "D3 workspaces.legacy_user_id", count: Number(d3!.n) });
  const [b1] = await q(`select count(*)::int as n ${B1}`);
  out.push({ check: "B1 pending invite addresses", count: Number(b1!.n) });
  return out;
}

async function main() {
  let q: Q, close: () => Promise<void>;
  if (gateway) {
    if (apply) throw new Error("--gateway is read-only; --apply is refused");
    const key = process.env.LOVABLE_API_KEY, conn = process.env.NEON_API_KEY;
    if (!key || !conn) throw new Error("LOVABLE_API_KEY and NEON_API_KEY are required for --gateway");
    q = async (s, p) => {
      if (!READ_ONLY.test(s)) throw new Error("refused: not a read-only statement");
      const res = await fetch("https://connector-gateway.lovable.dev/neon/sql", {
        method: "POST",
        headers: { Authorization: `Bearer ${key}`, "X-Connection-Api-Key": conn, "Content-Type": "application/json" },
        body: JSON.stringify({ query: `begin read only; ${s}`.replace(/^begin read only; /, ""), params: p ?? [] }),
      });
      const text = await res.text();
      if (!res.ok) throw new Error(`${res.status}: ${text.slice(0, 300)}`);
      return (JSON.parse(text) as { rows: Record<string, unknown>[] }).rows;
    };
    close = async () => {};
  } else if (urlEnv) {
    const url = process.env[urlEnv];
    if (!url) throw new Error(`${urlEnv} is not set`);
    const { Pool } = await import("@neondatabase/serverless");
    const pool = new Pool({ connectionString: url });
    q = async (s, p) => (await pool.query(s, p as unknown[])).rows;
    close = () => pool.end();
  } else {
    const { replayDb } = await import("./formal-rls/replay");
    const db = await replayDb();
    q = async (s, p) => (await db.query<Record<string, unknown>>(s, p as unknown[])).rows;
    close = () => db.close();
  }
  try {
    if (apply) {
      if (!urlEnv) throw new Error("--apply needs --url-env");
      for (;;) {
        const r = await q(`update public.workspace_invites set email = null where id in (select i.id ${B1} limit ${BATCH}) returning id`);
        if (r.length < BATCH) break;
      }
    }
    const res = await checks(q);
    const bad = res.filter((r) => r.count !== 0);
    console.log(`${res.length} checks, ${bad.length} with deviations${gateway ? " (live, read-only)" : urlEnv ? "" : " (offline replay)"}.`);
    for (const r of bad) console.log(`  ${r.check}: ${r.count}`);
    process.exitCode = bad.length ? 1 : 0;
  } finally {
    await close();
  }
}
if (import.meta.main) await main();
