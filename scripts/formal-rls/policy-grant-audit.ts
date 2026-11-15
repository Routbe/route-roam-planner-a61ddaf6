/**
 * Policy execute-rights audit: for every role that reaches a table through table privileges, every
 * function a policy on that table depends on (pg_depend, so nothing is parsed) must be executable by
 * that role. A missing EXECUTE turns every write through that policy into "permission denied".
 * Policies scoped to other roles are skipped (they never run for this role).
 */
export const AUDIT_ROLES = ["rout_app", "rout_merge_executor", "rout_omni_worker"] as const;

export const POLICY_GRANT_AUDIT_SQL = `
with r as (select unnest($1::text[]) as role),
pol as (
  select p.oid, c.oid as relid, n.nspname || '.' || c.relname as tbl, p.polname, p.polroles
    from pg_catalog.pg_policy p join pg_catalog.pg_class c on c.oid = p.polrelid
    join pg_catalog.pg_namespace n on n.oid = c.relnamespace
)
select distinct r.role, pol.tbl, pol.polname, fn.oid::regprocedure::text as fn
  from r cross join pol
  join pg_catalog.pg_depend d on d.classid = 'pg_catalog.pg_policy'::regclass and d.objid = pol.oid
   and d.refclassid = 'pg_catalog.pg_proc'::regclass
  join pg_catalog.pg_proc fn on fn.oid = d.refobjid
 where exists (select 1 from pg_catalog.pg_roles x where x.rolname = r.role)
   and (0 = any(pol.polroles) or (select oid from pg_catalog.pg_roles where rolname = r.role) = any(pol.polroles)
        or exists (select 1 from pg_catalog.pg_roles g where g.oid = any(pol.polroles) and pg_catalog.pg_has_role(r.role, g.oid, 'MEMBER')))
   and (pg_catalog.has_table_privilege(r.role, pol.relid, 'SELECT') or pg_catalog.has_table_privilege(r.role, pol.relid, 'INSERT')
        or pg_catalog.has_table_privilege(r.role, pol.relid, 'UPDATE') or pg_catalog.has_table_privilege(r.role, pol.relid, 'DELETE')
        or exists (select 1 from pg_catalog.pg_attribute a where a.attrelid = pol.relid and a.attnum > 0 and not a.attisdropped
                   and pg_catalog.has_column_privilege(r.role, pol.relid, a.attnum, 'SELECT,INSERT,UPDATE')))
   and not pg_catalog.has_function_privilege(r.role, fn.oid, 'EXECUTE')
 order by 1, 2, 3, 4`;

export type GrantGap = { role: string; tbl: string; polname: string; fn: string };
