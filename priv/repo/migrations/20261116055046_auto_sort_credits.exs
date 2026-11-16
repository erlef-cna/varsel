defmodule Varsel.Repo.Migrations.AutoSortCredits do
  @moduledoc """
  Turns a credit's one type into a list of types, drops its position, and
  makes a person unique per case by name and organization, ignoring case.

  The rows that credited one person more than once on the same case fold into
  the oldest of them. It carries every role, keeps its own name, and takes the
  account and the provider handles it lacks from the folded rows. Proposals
  follow the row they target, and proposals on a credit's position go.
  """

  use Ecto.Migration

  @types ~w(finder reporter analyst coordinator remediation_developer remediation_reviewer
            remediation_verifier sponsor tool other)

  def up do
    alter table(:case_credits) do
      add :credit_types, {:array, :text}
    end

    execute("UPDATE case_credits SET credit_types = ARRAY[credit_type]")

    execute("""
    CREATE TEMPORARY TABLE credit_merges ON COMMIT DROP AS
    SELECT id,
           credit_type,
           row_number() OVER person AS rank,
           first_value(id) OVER person AS keep_id
    FROM case_credits
    WINDOW person AS (
      PARTITION BY case_id, name::citext, organization::citext
      ORDER BY position, inserted_at, id
    )
    """)

    execute("""
    UPDATE case_credits AS kept
    SET credit_types = merged.credit_types,
        user_id = COALESCE(kept.user_id, merged.user_id)
    FROM (
      SELECT m.keep_id,
             #{sorted("array_agg(DISTINCT m.credit_type)")} AS credit_types,
             (array_agg(c.user_id ORDER BY m.rank) FILTER (WHERE c.user_id IS NOT NULL))[1] AS user_id
      FROM credit_merges AS m
      JOIN case_credits AS c ON c.id = m.id
      GROUP BY m.keep_id
    ) AS merged
    WHERE kept.id = merged.keep_id
    """)

    # A credit names a person by one handle per provider: the kept row's
    # handle for a provider stands, the folded rows fill the providers it lacks.
    execute("""
    UPDATE case_credits AS kept
    SET handles = merged.handles
    FROM (
      SELECT keep_id, array_agg(handle ORDER BY rank) AS handles
      FROM (
        SELECT DISTINCT ON (m.keep_id, h.handle ->> 'strategy')
               m.keep_id, m.rank, h.handle
        FROM credit_merges AS m
        JOIN case_credits AS c ON c.id = m.id
        CROSS JOIN unnest(c.handles) AS h(handle)
        ORDER BY m.keep_id, h.handle ->> 'strategy', m.rank
      ) AS per_provider
      GROUP BY keep_id
    ) AS merged
    WHERE kept.id = merged.keep_id
    """)

    # A proposal to change the type of a folded row changes that one role of
    # the merged credit.
    execute("""
    UPDATE case_proposals AS p
    SET field_name = 'credit_types',
        proposed_value = jsonb_set(
          p.proposed_value,
          '{value}',
          to_jsonb(#{sorted("array_remove(k.credit_types, m.credit_type) || (p.proposed_value ->> 'value')")})
        )
    FROM credit_merges AS m
    JOIN case_credits AS k ON k.id = m.keep_id
    WHERE p.target = 'credit' AND p.field_name = 'credit_type' AND p.target_id = m.id
    """)

    execute("""
    UPDATE case_proposals AS p
    SET target_id = m.keep_id
    FROM credit_merges AS m
    WHERE p.target = 'credit' AND p.target_id = m.id AND m.id <> m.keep_id
    """)

    execute(
      "DELETE FROM case_credits WHERE id IN (SELECT id FROM credit_merges WHERE id <> keep_id)"
    )

    execute("DELETE FROM case_proposals WHERE target = 'credit' AND field_name = 'position'")

    execute("""
    UPDATE case_proposals
    SET proposed_value = jsonb_set(
          proposed_value #- '{value,credit_type}' #- '{value,position}',
          '{value,credit_types}',
          CASE
            WHEN proposed_value -> 'value' ? 'credit_type'
              THEN jsonb_build_array(proposed_value -> 'value' -> 'credit_type')
            ELSE '["finder"]'::jsonb
          END
        )
    WHERE target = 'credit' AND operation = 'insert'
      AND jsonb_typeof(proposed_value -> 'value') = 'object'
    """)

    alter table(:case_credits) do
      modify :credit_types, {:array, :text}, null: false
      remove :credit_type
      remove :position
    end

    create unique_index(:case_credits, [:case_id, "((name::citext))", "((organization::citext))"],
             name: "case_credits_unique_person_index",
             nulls_distinct: false
           )
  end

  def down do
    drop_if_exists unique_index(
                     :case_credits,
                     [:case_id, "((name::citext))", "((organization::citext))"],
                     name: "case_credits_unique_person_index"
                   )

    alter table(:case_credits) do
      add :position, :bigint, null: false, default: 0
      add :credit_type, :text, null: false, default: "finder"
    end

    execute("UPDATE case_credits SET credit_type = credit_types[1]")

    execute("""
    INSERT INTO case_credits
      (id, case_id, user_id, name, organization, handles, credit_types, credit_type,
       inserted_at, updated_at)
    SELECT gen_random_uuid(), case_id, user_id, name, organization, handles, credit_types, t,
           inserted_at, updated_at
    FROM case_credits
    CROSS JOIN unnest(credit_types[2:]) AS t
    """)

    execute("""
    UPDATE case_credits AS c
    SET position = ordered.position
    FROM (
      SELECT id,
             row_number() OVER (
               PARTITION BY case_id
               ORDER BY lower(name), name, array_position(#{types_array()}, credit_type), id
             ) - 1 AS position
      FROM case_credits
    ) AS ordered
    WHERE c.id = ordered.id
    """)

    execute("""
    UPDATE case_proposals
    SET field_name = 'credit_type',
        proposed_value = jsonb_set(proposed_value, '{value}', proposed_value -> 'value' -> 0)
    WHERE target = 'credit' AND field_name = 'credit_types'
    """)

    execute("""
    UPDATE case_proposals
    SET proposed_value = jsonb_set(
          proposed_value #- '{value,credit_types}',
          '{value,credit_type}',
          COALESCE(proposed_value -> 'value' -> 'credit_types' -> 0, '"finder"'::jsonb)
        )
    WHERE target = 'credit' AND operation = 'insert'
      AND jsonb_typeof(proposed_value -> 'value') = 'object'
    """)

    alter table(:case_credits) do
      remove :credit_types
    end
  end

  defp types_array, do: "ARRAY[" <> Enum.map_join(@types, ", ", &"'#{&1}'") <> "]"

  defp sorted(array) do
    "ARRAY(SELECT t FROM (SELECT DISTINCT unnest(#{array}) AS t) AS d " <>
      "ORDER BY array_position(#{types_array()}, t))"
  end
end
