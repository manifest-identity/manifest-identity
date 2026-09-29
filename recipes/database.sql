-- PostgreSQL role memberships to the observed table (subphase 1.14a).
--
-- Run as any role that can read pg_roles, from psql, naming the
-- instance the door should file these under:
--   psql -v instance=prod-db -f recipes/database.sql
-- which writes observed.csv in the current directory.
--
-- One row per membership, plus one row per superuser holding the
-- built-in "superuser" attribute, which is a grant without a group. A
-- role that can log in is an identity; one that cannot is a group other
-- roles inherit from, and appears here as the role being held. The
-- identity is the role's object identifier, which the instance never
-- reuses while the role exists.
\copy (
  SELECT 'database' AS provider,
         :'instance' AS account,
         r.oid::text AS identity_id,
         r.rolname AS identity_name,
         'role' AS identity_type,
         CASE WHEN r.rolcanlogin THEN 'unknown' ELSE 'group' END AS identity_kind,
         g.rolname AS role,
         g.rolname AS role_name,
         'standing' AS mode,
         '' AS path
    FROM pg_auth_members m
    JOIN pg_roles r ON r.oid = m.member
    JOIN pg_roles g ON g.oid = m.roleid
   WHERE r.rolname NOT LIKE 'pg\_%'
  UNION ALL
  SELECT 'database', :'instance', r.oid::text, r.rolname, 'role',
         CASE WHEN r.rolcanlogin THEN 'unknown' ELSE 'group' END,
         'superuser', 'superuser', 'standing', ''
    FROM pg_roles r
   WHERE r.rolsuper AND r.rolname NOT LIKE 'pg\_%'
   ORDER BY 3, 7
) TO 'observed.csv' WITH (FORMAT csv, HEADER true)
