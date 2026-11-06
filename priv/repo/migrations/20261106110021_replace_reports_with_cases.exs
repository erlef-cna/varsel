defmodule Varsel.Repo.Migrations.ReplaceReportsWithCases do
  @moduledoc """
  Moves the triage decision from the report to the case.

  Every case that exists was accepted. A report that was never accepted gets
  a case of its own, in the state that matches its own. The people named on
  a report still awaiting a decision are invited onto its case, as a new
  report's people are.

  Rolling back keeps only the accepted cases. Report participants do not
  come back.
  """

  use Ecto.Migration

  def up do
    create table(:case_reports_versions, primary_key: false) do
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

    create table(:case_reports, primary_key: false) do
      add :id, :uuid, null: false, default: fragment("gen_random_uuid()"), primary_key: true

      add :inserted_at, :utc_datetime_usec,
        null: false,
        default: fragment("(now() AT TIME ZONE 'utc')")

      add :updated_at, :utc_datetime_usec,
        null: false,
        default: fragment("(now() AT TIME ZONE 'utc')")

      add :case_id,
          references(:cases,
            column: :id,
            name: "case_reports_case_id_fkey",
            type: :uuid,
            prefix: "public",
            on_delete: :delete_all
          ),
          null: false

      add :vulnerability_report_id,
          references(:vulnerability_reports,
            column: :id,
            name: "case_reports_vulnerability_report_id_fkey",
            type: :uuid,
            prefix: "public",
            on_delete: :delete_all
          ),
          null: false
    end

    create unique_index(:case_reports, [:case_id, :vulnerability_report_id],
             name: "case_reports_unique_case_report_index"
           )

    alter table(:cases) do
      add :accepted_at, :utc_datetime_usec

      add :merged_into_id,
          references(:cases,
            column: :id,
            name: "cases_merged_into_id_fkey",
            type: :uuid,
            prefix: "public",
            on_delete: :nilify_all
          )
    end

    alter table(:vulnerability_reports) do
      add :reporter_strategy, :text
      add :reporter_username, :citext
      add :opened_case_id, :uuid
    end

    flush()

    execute "UPDATE cases SET accepted_at = inserted_at"

    execute """
    UPDATE vulnerability_reports r
    SET reporter_strategy = p.strategy, reporter_username = p.username
    FROM report_participants p
    WHERE p.report_id = r.id AND p.role = 'reporter'
    """

    execute """
    INSERT INTO case_reports (case_id, vulnerability_report_id, inserted_at, updated_at)
    SELECT case_id, id, updated_at, updated_at
    FROM vulnerability_reports
    WHERE case_id IS NOT NULL
    """

    execute """
    UPDATE vulnerability_reports
    SET opened_case_id = gen_random_uuid()
    WHERE case_id IS NULL
    """

    execute """
    INSERT INTO cases (id, title, state, closed_reason, inserted_at, updated_at)
    SELECT
      opened_case_id,
      summary,
      CASE state
        WHEN 'submitted' THEN 'submitted'
        WHEN 'triaged' THEN 'triage'
        ELSE 'closed'
      END,
      CASE WHEN state = 'rejected' THEN triage_notes END,
      inserted_at,
      updated_at
    FROM vulnerability_reports
    WHERE opened_case_id IS NOT NULL
    """

    execute """
    INSERT INTO case_reports (case_id, vulnerability_report_id, inserted_at, updated_at)
    SELECT opened_case_id, id, inserted_at, inserted_at
    FROM vulnerability_reports
    WHERE opened_case_id IS NOT NULL
    """

    execute """
    INSERT INTO case_assignments (case_id, user_id, inserted_at, updated_at)
    SELECT opened_case_id, reporter_id, inserted_at, inserted_at
    FROM vulnerability_reports
    WHERE opened_case_id IS NOT NULL AND reporter_id IS NOT NULL
    ON CONFLICT (case_id, user_id) DO NOTHING
    """

    execute """
    INSERT INTO case_assignments (case_id, user_id, note, inserted_at, updated_at)
    SELECT r.opened_case_id, p.user_id, #{note_sql()}, p.inserted_at, p.inserted_at
    FROM report_participants p
    JOIN vulnerability_reports r ON r.id = p.report_id
    WHERE r.state IN ('submitted', 'triaged') AND p.user_id IS NOT NULL
    ON CONFLICT (case_id, user_id) DO NOTHING
    """

    execute """
    INSERT INTO case_invites
      (case_id, strategy, username, email, email_status, note, inserted_at, updated_at)
    SELECT
      r.opened_case_id,
      p.strategy,
      p.username,
      p.email,
      CASE WHEN p.email IS NULL THEN 'skipped' ELSE 'pending' END,
      #{note_sql()},
      p.inserted_at,
      p.inserted_at
    FROM report_participants p
    JOIN vulnerability_reports r ON r.id = p.report_id
    WHERE r.state IN ('submitted', 'triaged') AND p.user_id IS NULL
    ON CONFLICT (case_id, strategy, username) DO NOTHING
    """

    execute """
    UPDATE notifications n
    SET case_id = cr.case_id
    FROM case_reports cr
    WHERE n.case_id IS NULL AND n.vulnerability_report_id = cr.vulnerability_report_id
    """

    execute "DELETE FROM notifications WHERE case_id IS NULL"

    # Two accepted reports on one case leave two unread notifications for it.
    execute """
    DELETE FROM notifications n
    USING notifications earlier
    WHERE n.read_at IS NULL AND earlier.read_at IS NULL
      AND n.user_id = earlier.user_id AND n.kind = earlier.kind AND n.case_id = earlier.case_id
      AND (earlier.inserted_at, earlier.id) < (n.inserted_at, n.id)
    """

    drop_if_exists unique_index(
                     :notifications,
                     [:user_id, :kind, :case_id, :vulnerability_report_id],
                     name: "notifications_unread_per_subject_index"
                   )

    alter table(:notifications) do
      modify :case_id, :uuid, null: false
      remove :vulnerability_report_id
    end

    create unique_index(:notifications, [:user_id, :kind, :case_id],
             name: "notifications_unread_per_subject_index",
             nulls_distinct: false,
             where: "(read_at IS NULL)"
           )

    drop table(:report_participants)

    drop table(:report_participants_versions)

    alter table(:vulnerability_reports_versions) do
      remove :state
    end

    alter table(:vulnerability_reports) do
      remove :opened_case_id
      remove :version
      remove :triage_notes
      remove :state
      remove :case_id
    end
  end

  def down do
    alter table(:vulnerability_reports) do
      add :case_id,
          references(:cases,
            column: :id,
            name: "vulnerability_reports_case_id_fkey",
            type: :uuid,
            prefix: "public"
          )

      add :state, :text, null: false, default: "submitted"
      add :triage_notes, :text
      add :version, :bigint, null: false, default: 1
    end

    alter table(:vulnerability_reports_versions) do
      add :state, :text, null: false, default: "submitted"
    end

    flush()

    execute """
    UPDATE vulnerability_reports r
    SET case_id = c.id, state = 'accepted'
    FROM case_reports cr
    JOIN cases c ON c.id = cr.case_id
    WHERE cr.vulnerability_report_id = r.id AND c.accepted_at IS NOT NULL
    """

    execute """
    UPDATE vulnerability_reports r
    SET
      state = CASE c.state
        WHEN 'submitted' THEN 'submitted'
        WHEN 'triage' THEN 'triaged'
        ELSE 'rejected'
      END,
      triage_notes = c.closed_reason
    FROM case_reports cr
    JOIN cases c ON c.id = cr.case_id
    WHERE cr.vulnerability_report_id = r.id AND r.case_id IS NULL AND c.accepted_at IS NULL
    """

    alter table(:notifications) do
      add :vulnerability_report_id,
          references(:vulnerability_reports,
            column: :id,
            name: "notifications_vulnerability_report_id_fkey",
            type: :uuid,
            prefix: "public",
            on_delete: :delete_all
          )
    end

    flush()

    execute """
    DELETE FROM notifications n
    USING cases c
    WHERE n.case_id = c.id AND c.accepted_at IS NULL
    """

    execute "DELETE FROM cases WHERE accepted_at IS NULL"

    drop_if_exists unique_index(:notifications, [:user_id, :kind, :case_id],
                     name: "notifications_unread_per_subject_index"
                   )

    alter table(:notifications) do
      modify :case_id, :uuid, null: true
    end

    create unique_index(:notifications, [:user_id, :kind, :case_id, :vulnerability_report_id],
             name: "notifications_unread_per_subject_index",
             nulls_distinct: false,
             where: "(read_at IS NULL)"
           )

    drop constraint(:cases, "cases_merged_into_id_fkey")

    alter table(:cases) do
      remove :merged_into_id
      remove :accepted_at
    end

    drop constraint(:case_reports, "case_reports_vulnerability_report_id_fkey")

    drop constraint(:case_reports, "case_reports_case_id_fkey")

    drop_if_exists unique_index(:case_reports, [:case_id, :vulnerability_report_id],
                     name: "case_reports_unique_case_report_index"
                   )

    drop table(:case_reports)

    drop table(:case_reports_versions)

    alter table(:vulnerability_reports) do
      remove :reporter_username
      remove :reporter_strategy
    end

    create table(:report_participants, primary_key: false) do
      add :id, :uuid, null: false, default: fragment("gen_random_uuid()"), primary_key: true
      add :role, :text, null: false
      add :strategy, :text, null: false
      add :username, :citext, null: false
      add :email, :text

      add :inserted_at, :utc_datetime_usec,
        null: false,
        default: fragment("(now() AT TIME ZONE 'utc')")

      add :updated_at, :utc_datetime_usec,
        null: false,
        default: fragment("(now() AT TIME ZONE 'utc')")

      add :report_id,
          references(:vulnerability_reports,
            column: :id,
            name: "report_participants_report_id_fkey",
            type: :uuid,
            prefix: "public",
            on_delete: :delete_all
          ),
          null: false

      add :user_id,
          references(:users,
            column: :id,
            name: "report_participants_user_id_fkey",
            type: :uuid,
            prefix: "public",
            on_delete: :nilify_all
          )
    end

    create unique_index(:report_participants, [:report_id, :role, :strategy, :username],
             name: "report_participants_unique_report_handle_index"
           )

    create table(:report_participants_versions, primary_key: false) do
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

  # The notes `Varsel.Cases.Case.Changes.AdmitNamedPeople` writes for a hex.pm
  # report's people.
  defp note_sql do
    """
    CASE p.role
      WHEN 'reporter' THEN 'Reported the issue on hex.pm'
      ELSE 'Maintains ' || (r.report_json->>'package') || ' on hex.pm'
    END
    """
  end
end
