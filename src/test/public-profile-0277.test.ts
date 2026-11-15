// @vitest-environment node
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { replayDb } from "../../scripts/formal-rls/replay";

describe("public profile projection under 0277 column grants", () => {
 it("reads the actual public query anonymously but rejects a whole-row projection", async () => {
  const db = await replayDb();
  try {
   const source = readFileSync("src/lib/studio-profile.server.ts", "utf8");
   const query = source.split("export async function readPublicProfile")[1]?.match(/await sql`([\s\S]*?)`/)?.[1];
   if (!query) throw new Error("Public query not found");
   await db.exec("set role rout_app");
   await expect(db.query(query.replace(/\$\{username\}/g, "'not-a-real-handle'"))).resolves.toMatchObject({ rows: [] });
   await expect(db.query("select to_jsonb(profiles) from public.profiles limit 1")).rejects.toThrow(/permission denied/);
  } finally { await db.close(); }
 }, 120000);
});