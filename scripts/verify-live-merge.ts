/** Read-only merge capability probe. Never calls execute_account_merge or changes members. */
import { replayDb } from "./formal-rls/replay";

const RELEASE = "select exists(select 1 from public.schema_migrations where filename = '0277_tenant_contract_and_merge_fix.sql' and checksum = '2ae4306fa351d7c7a486fc40f09f1c4079970717127b37c899729c6c0b5250f8') as released";
const GRANTS = "select count(*) filter(where has_function_privilege('rout_merge_executor',f,'EXECUTE'))::int as grants from unnest(array['public.rout_is_workspace_member(uuid)','public.rout_tenant_ref_kept(text,uuid,uuid)','public.current_app_user_id()','public.rout_workspace_claimable(uuid)','public.rout_workspace_role(uuid)','public.rout_caller_is_admin()']) f";

export const MERGE_PROBE = `select current_user as role,
 public.rout_is_workspace_member(null::uuid) as member,
 public.rout_tenant_ref_kept('profiles', null::uuid, null::uuid) as kept,
 public.current_app_user_id() as caller,
 public.rout_workspace_claimable(null::uuid) as claimable,
 public.rout_workspace_role(null::uuid) as workspace_role,
 public.rout_caller_is_admin() as admin`;

export async function main() {
 const gateway = process.argv.includes("--gateway");
 const grantsOnly = process.argv.includes("--grants-only");
 if (gateway) {
  const key = process.env.LOVABLE_API_KEY, connection = process.env.NEON_API_KEY;
  if (!key || !connection) throw new Error("Neon connector unavailable");
  const response = await fetch("https://connector-gateway.lovable.dev/neon/sql", {
   method: "POST", headers: { Authorization: `Bearer ${key}`, "X-Connection-Api-Key": connection, "Content-Type": "application/json" },
   body: JSON.stringify({ queries: [
    { query: "set transaction read only", params: [] },
    { query: RELEASE, params: [] },
    ...(grantsOnly ? [{ query: GRANTS, params: [] }] : [{ query: "set local role rout_merge_executor", params: [] }, { query: MERGE_PROBE, params: [] }]),
   ] }),
  });
  if (!response.ok) {
   const error = await response.json() as { code?: string };
   throw new Error(`Live probe failed: HTTP ${response.status}, SQLSTATE ${error.code ?? "unknown"}. No privileges changed. --grants-only checks rights, not execution.`);
  }
  const result = await response.json();
  const text = JSON.stringify(result);
  if (!text.includes('"released":true') || !(grantsOnly ? text.includes('"grants":6') : text.includes('"role":"rout_merge_executor"'))) throw new Error("0277 or executor rights not confirmed");
  console.log(grantsOnly ? "Live 0277 fingerprint verified; 6/6 EXECUTE rights confirmed. Execution as executor NOT tested." : "Live 0277 fingerprint verified; all six helpers executed as rout_merge_executor (read-only, anonymous scope). No accounts merged.");
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