defmodule Varsel.Repo.Migrations.AddCweWeaknessClosure do
  @moduledoc """
  Hand-written migration (the resource sets `migrate? false`): creates the
  `cwe_weakness_closure` materialized view holding the transitive closure of
  `child_of` weakness relationships per CWE view, plus fully-recursive
  NULL-parent view-root rows.
  """

  use Ecto.Migration

  def up do
    execute("""
    CREATE MATERIALIZED VIEW cwe_weakness_closure AS
    WITH RECURSIVE descendants AS (
      -- Every CWE appearing in a child_of edge is included in its own subtree.
      SELECT r.view_id,
             r.source_cwe_id AS parent_cwe_id,
             r.source_cwe_id AS descendant_cwe_id,
             ARRAY[r.source_cwe_id] AS path
      FROM cwe_weakness_relationships AS r
      WHERE r.nature = 'child_of'

      UNION

      SELECT r.view_id, r.target_cwe_id, r.target_cwe_id, ARRAY[r.target_cwe_id]
      FROM cwe_weakness_relationships AS r
      WHERE r.nature = 'child_of'

      UNION

      -- Declared view members: self-pair (a member with no children in the
      -- view must still be countable as parent_cwe_id = member) ...
      SELECT m.view_id, m.cwe_id, m.cwe_id, ARRAY[m.cwe_id]
      FROM cwe_view_memberships AS m

      UNION

      -- ... and the NULL-parent seed: NULL is the view root, so its closure
      -- covers everything reachable from any declared member.
      SELECT m.view_id, NULL::bigint, m.cwe_id, ARRAY[m.cwe_id]
      FROM cwe_view_memberships AS m

      UNION ALL

      -- Walk from a parent to its children, never crossing views.
      SELECT d.view_id, d.parent_cwe_id, r.source_cwe_id, d.path || r.source_cwe_id
      FROM descendants AS d
      JOIN cwe_weakness_relationships AS r
        ON r.view_id = d.view_id
       AND r.nature = 'child_of'
       AND r.target_cwe_id = d.descendant_cwe_id
      WHERE NOT r.source_cwe_id = ANY(d.path)
    )
    -- DISTINCT collapses the many paths through which a graph node is reachable.
    SELECT DISTINCT view_id, parent_cwe_id, descendant_cwe_id
    FROM descendants
    """)

    execute("""
    CREATE UNIQUE INDEX cwe_weakness_closure_unique_idx
    ON cwe_weakness_closure (view_id, parent_cwe_id, descendant_cwe_id)
    NULLS NOT DISTINCT
    """)

    execute("""
    CREATE INDEX cwe_child_of_relationships_idx
    ON cwe_weakness_relationships (view_id, target_cwe_id, source_cwe_id)
    WHERE nature = 'child_of'
    """)
  end

  def down do
    execute("DROP INDEX IF EXISTS cwe_child_of_relationships_idx")
    execute("DROP INDEX IF EXISTS cwe_weakness_closure_unique_idx")
    execute("DROP MATERIALIZED VIEW IF EXISTS cwe_weakness_closure")
  end
end
