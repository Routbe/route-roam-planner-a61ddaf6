/** Read-only merge capability probe. Never calls execute_account_merge or changes members. */
import { replayDb } from "./formal-rls/replay";

export const MERGE_PROBE = `select current_user as role,
 public.rout_is_workspace_member(null::uuid) as member,
 public.rout_tenant_ref_kept('profiles', null::uuid, null::uuid) as kept,
 public.current_app_user_id() as caller,
 public.rout_workspace_claimable(null::uuid) as claimable,
 public.rout_workspace_role(null::uuid) as workspace_role,
 public.rout_caller_is_admin() as admin`;

export async function main() {
 const gateway = process.argv.includes("--gateway");
 if (gateway) {
  const key = process.env.LOVABLE_API_KEY, connection = process.env.NEON_API_KEY;
  if (!key || !connection) throw new Error("Neon connector unavailable");
  const response = await fetch("https://connector-gateway.lovable.dev/neon/sql", {
   method: "POST", headers: { Authorization: `Bearer ${key}`, "X-Connection-Api-Key": connection, "Content-Type": "application/json" },
   body: JSON.stringify({ queries: [
    { query: "set transaction read only", params: [] },
    { query: "select exists(select 1 from public.schema_migrations where filename = '0277_tenant_contract_and_merge_fix.sql' and checksum = '2ae4306fa351d7c7a486fc40f09f1c4079970717127b37c899729c6c0b5250f8') as released", params: [] },
    { query: "set local role rout_merge_executor", params: [] },
    { query: MERGE_PROBE, params: [] },
   ] }),
  });
  if (!response.ok) throw new Error(`Live probe failed: HTTP ${response.status}`);
  const result = await response.json();
  const text = JSON.stringify(result);
  if (!text.includes('"released":true') || !text.includes('"role":"rout_merge_executor"')) throw new Error("0277 or executor role not confirmed");
  console.log("Live 0277 fingerprint verified; all six helpers executed as rout_merge_executor (read-only, anonymous scope). No accounts merged.");
 } else {
  const db = await replayDb();
  try { await db.exec("begin read only; set local role rout_merge_executor");
   const result = await db.query(MERGE_PROBE);
   if (result.rows.length !== 1) throw new Error("No probe result");
   console.log("Offline: all six helpers executed as rout_merge_executor.");
  } finally { await db.exec("rollback"); await db.close(); }
 }
}
if (import.meta.main) await main();