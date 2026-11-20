defmodule Varsel.Repo.Migrations.MultipleCvssScenarios do
  @moduledoc """
  Moves the case's CVSS vector into `case_metrics`, one row per scenario.

  Each case's `cvss_v4` becomes its GENERAL metric. Proposals that targeted
  the case's `cvss_v4` field now target that metric. An open proposal for a
  case without a score becomes a proposal to insert the GENERAL metric.
  """

  use Ecto.Migration

  def up do
    create table(:case_metrics, primary_key: false) do
      add :id, :uuid, null: false, default: fragment("gen_random_uuid()"), primary_key: true
      add :scenario, :text, null: false, default: "GENERAL"
      add :cvss_v4, :map, null: false

      add :inserted_at, :utc_datetime_usec,
        null: false,
        default: fragment("(now() AT TIME ZONE 'utc')")

      add :updated_at, :utc_datetime_usec,
        null: false,
        default: fragment("(now() AT TIME ZONE 'utc')")

      add :case_id,
          references(:cases,
            column: :id,
            name: "case_metrics_case_id_fkey",
            type: :uuid,
            prefix: "public",
            on_delete: :delete_all
          ),
          null: false
    end

    create unique_index(:case_metrics, [:case_id, :scenario],
             name: "case_metrics_unique_case_scenario_index"
           )

    execute("""
    INSERT INTO case_metrics (case_id, scenario, cvss_v4)
    SELECT id, 'GENERAL', cvss_v4 FROM cases WHERE cvss_v4 IS NOT NULL
    """)

    execute("""
    UPDATE case_proposals AS p
    SET target = 'metric', target_id = m.id
    FROM case_metrics AS m
    WHERE p.target = 'case' AND p.field_name = 'cvss_v4'
      AND m.case_id = p.case_id AND m.scenario = 'GENERAL'
    """)

    # The metric's vector cannot be nil: proposing to clear it proposes removing the metric.
    execute("""
    UPDATE case_proposals
    SET operation = 'delete', field_name = NULL, proposed_value = NULL
    WHERE target = 'metric' AND field_name = 'cvss_v4' AND state = 'open'
      AND target_id IS NOT NULL AND proposed_value->>'value' IS NULL
    """)

    execute("""
    UPDATE case_proposals
    SET target = 'metric', operation = 'insert', field_name = NULL,
        proposed_value = jsonb_build_object(
          'value',
          jsonb_build_object('scenario', 'GENERAL', 'cvss_v4', proposed_value->'value')
        )
    WHERE target = 'case' AND field_name = 'cvss_v4' AND state = 'open'
      AND proposed_value->>'value' IS NOT NULL
    """)

    execute("""
    UPDATE case_proposals SET target = 'metric'
    WHERE target = 'case' AND field_name = 'cvss_v4'
    """)

    alter table(:cases) do
      remove :cvss_v4
    end

    create table(:case_metrics_versions, primary_key: false) do
      add :id, :uuid, null: false, default: fragment("gen_random_uuid()"), primary_key: true
      add :version_action_type, :text, null: false
      add :version_action_name, :text, null: false
      add :version_source_id, :uuid, null: false
      add :changes, :map

      add :version_inserted_at, :utc_datetime_usec,
        null: false,
        default: fragment("(now() AT TIME ZONE 'utc')")

      add :version_updated_at, :utc_datetime_usec,
        null: false,
        default: fragment("(now() AT TIME ZONE 'utc')")

      add :user_id, :uuid
    end
  end

  def down do
    # A case column holds one vector, so a scenario other than GENERAL, and
    # every proposal about one, has no place to go back to.
    execute("""
    DO $$
    BEGIN
      IF EXISTS (SELECT 1 FROM case_metrics WHERE scenario <> 'GENERAL')
         OR EXISTS (
           SELECT 1 FROM case_proposals
           WHERE target = 'metric'
             AND (field_name = 'scenario'
                  OR (operation = 'insert'
                      AND proposed_value->'value'->>'scenario' IS DISTINCT FROM 'GENERAL'))
         )
      THEN
        RAISE EXCEPTION 'case_metrics holds scenarios other than GENERAL; remove them before rolling back';
      END IF;
    END
    $$
    """)

    drop table(:case_metrics_versions)

    alter table(:cases) do
      add :cvss_v4, :map
    end

    execute("""
    UPDATE cases AS c SET cvss_v4 = m.cvss_v4
    FROM case_metrics AS m
    WHERE m.case_id = c.id AND m.scenario = 'GENERAL'
    """)

    execute("""
    UPDATE case_proposals
    SET target = 'case', target_id = NULL, operation = 'set', field_name = 'cvss_v4',
        proposed_value = jsonb_build_object('value', proposed_value->'value'->'cvss_v4')
    WHERE target = 'metric' AND operation = 'insert'
    """)

    execute("""
    UPDATE case_proposals
    SET target = 'case', target_id = NULL, operation = 'set', field_name = 'cvss_v4',
        proposed_value = '{"value": null}'::jsonb
    WHERE target = 'metric' AND operation = 'delete'
    """)

    execute("""
    UPDATE case_proposals SET target = 'case', target_id = NULL
    WHERE target = 'metric' AND field_name = 'cvss_v4'
    """)

    drop constraint(:case_metrics, "case_metrics_case_id_fkey")

    drop_if_exists unique_index(:case_metrics, [:case_id, :scenario],
                     name: "case_metrics_unique_case_scenario_index"
                   )

    drop table(:case_metrics)
  end
end
