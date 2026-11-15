/** Offline PGlite replay of db/ (same order and guard as the runners). Never touches Neon. */
import { PGlite } from "@electric-sql/pglite";
import { btree_gist } from "@electric-sql/pglite/contrib/btree_gist";
import { pgcrypto } from "@electric-sql/pglite/contrib/pgcrypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { listMigrationFiles, planMigrations } from "../migration-plan";
import { guardedMigration, migrationDefinerGuardSql } from "../security-definer-policy";

export const ROOT = join(import.meta.dir, "..", "..");

export async function replayDb(): Promise<PGlite> {
  const db = new PGlite({ extensions: { pgcrypto, btree_gist } });
  const dir = join(ROOT, "db");
  for (const step of planMigrations(listMigrationFiles(dir), new Set())) {
    if (step.action !== "run") continue;
    const guard = guardedMigration(step.file) ? `;\n${migrationDefinerGuardSql(step.file)}` : "";
    await db.exec(`begin;\n${readFileSync(join(dir, step.file), "utf8")}\n${guard};commit;`);
  }
  return db;
}

export async function applyPending(db: PGlite, file: string) {
  const body = readFileSync(join(ROOT, "db-pending", file), "utf8");
  await db.exec(`begin;\n${body}\n;\n${migrationDefinerGuardSql(file)};\ncommit;`);
}
