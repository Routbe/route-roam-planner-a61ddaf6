# Z3 certification — db-pending/0277_tenant_contract_and_merge_fix.sql

Run: 2026-11-15T13:13:55.516Z · offline PGlite replay of db/ (0277 included) · Neon not contacted

- Obligations: 1210, Z3 checks: 544
- proven (unsat): 1170 · declassified (reviewed): 10 · service boundary: 30 · unproven: 0
- SECURITY DEFINER without pg_catalog, pg_temp: 0 of 424
- New findings: 0 · findings 0277 must close still open: 0 · unused model entries: 0

**Result: CERTIFIED**


Certification is a precondition for 0277, not a GO: 0277 stays in db-pending/ until production reports
schema >= 0276, `scripts/tenant-backfill.ts` reports 0 deviations and the owner gives a separate GO.
