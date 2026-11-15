// @vitest-environment node
/**
 * Every role that reaches a table must be able to execute every helper a policy on that table
 * depends on (0276 broke account merge this way). Checked on a replay of db/ plus the held-back
 * 0277, which carries the grants for rout_merge_executor. Nothing touches Neon.
 */
import { afterAll, beforeAll, expect, it } from "vitest";
import type { PGlite } from "@electric-sql/pglite";
import { applyReleased, replayDb } from "../../scripts/formal-rls/replay";
import { AUDIT_ROLES, POLICY_GRANT_AUDIT_SQL } from "../../scripts/formal-rls/policy-grant-audit";

let db: PGlite;
const gaps = async () => (await db.query<{ role: string; fn: string }>(POLICY_GRANT_AUDIT_SQL, [AUDIT_ROLES as unknown as string[]])).rows;
// db/ up to 0276, then 0277 explicitly, so the test shows the gap 0277 closed.
beforeAll(async () => { db = await replayDb((f) => f < "0277"); }, 300_000);
afterAll(async () => { await db?.close(); });

it("db/ up to 0276 has the merge-executor gap that 0277 closes", async () => {
  expect((await gaps()).some((g) => g.role === "rout_merge_executor" && g.fn === "rout_is_workspace_member(uuid)")).toBe(true);
});
it("after 0277 no audited role misses EXECUTE on a policy helper", async () => {
  await applyReleased(db, "0277_tenant_contract_and_merge_fix.sql");
  expect(await gaps()).toEqual([]);
}, 120_000);
