// @vitest-environment node
import { describe, it, expect } from "vitest";
import { replayDb } from "../../scripts/formal-rls/replay";
import { MERGE_PROBE } from "../../scripts/verify-live-merge";

describe("0277 merge helper dry probe", () => {
 it("executes all six helpers without a member context", async () => {
  const db = await replayDb();
  try {
   await db.exec("begin read only; set local role rout_merge_executor");
   const { rows } = await db.query<Record<string, unknown>>(MERGE_PROBE);
   expect(rows[0]).toEqual({ role: "rout_merge_executor", member: false, kept: false, caller: null, claimable: false, workspace_role: null, admin: false });
  } finally { await db.exec("rollback"); await db.close(); }
 }, 120000);
});