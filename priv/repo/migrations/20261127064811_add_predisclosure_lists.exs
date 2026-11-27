defmodule Varsel.Repo.Migrations.AddPredisclosureLists do
  @moduledoc """
  Adds pre-disclosure lists, their subscribers and the cases on them, each
  with its paper trail.
  """

  use Ecto.Migration

  def up do
    create table(:predisclosure_list_subscribers_versions, primary_key: false) do
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

    create table(:predisclosure_lists, primary_key: false) do
      add :id, :uuid, null: false, default: fragment("gen_random_uuid()"), primary_key: true
      add :name, :text, null: false

      add :inserted_at, :utc_datetime_usec,
        null: false,
        default: fragment("(now() AT TIME ZONE 'utc')")

      add :updated_at, :utc_datetime_usec,
        null: false,
        default: fragment("(now() AT TIME ZONE 'utc')")
    end

    create unique_index(:predisclosure_lists, [:name],
             name: "predisclosure_lists_unique_name_index"
           )

    create table(:predisclosure_lists_versions, primary_key: false) do
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

    create table(:predisclosure_list_members, primary_key: false) do
      add :id, :uuid, null: false, default: fragment("gen_random_uuid()"), primary_key: true

      add :inserted_at, :utc_datetime_usec,
        null: false,
        default: fragment("(now() AT TIME ZONE 'utc')")

      add :updated_at, :utc_datetime_usec,
        null: false,
        default: fragment("(now() AT TIME ZONE 'utc')")

      add :list_id,
          references(:predisclosure_lists,
            column: :id,
            name: "predisclosure_list_members_list_id_fkey",
            type: :uuid,
            prefix: "public",
            on_delete: :delete_all
          ),
          null: false

      add :case_id,
          references(:cases,
            column: :id,
            name: "predisclosure_list_members_case_id_fkey",
            type: :uuid,
            prefix: "public",
            on_delete: :delete_all
          ),
          null: false
    end

    create unique_index(:predisclosure_list_members, [:list_id, :case_id],
             name: "predisclosure_list_members_unique_list_case_index"
           )

    create table(:predisclosure_list_members_versions, primary_key: false) do
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

    create table(:predisclosure_list_subscribers, primary_key: false) do
      add :id, :uuid, null: false, default: fragment("gen_random_uuid()"), primary_key: true

      add :inserted_at, :utc_datetime_usec,
        null: false,
        default: fragment("(now() AT TIME ZONE 'utc')")

      add :updated_at, :utc_datetime_usec,
        null: false,
        default: fragment("(now() AT TIME ZONE 'utc')")

      add :list_id,
          references(:predisclosure_lists,
            column: :id,
            name: "predisclosure_list_subscribers_list_id_fkey",
            type: :uuid,
            prefix: "public",
            on_delete: :delete_all
          ),
          null: false

      add :user_id,
          references(:users,
            column: :id,
            name: "predisclosure_list_subscribers_user_id_fkey",
            type: :uuid,
            prefix: "public",
            on_delete: :delete_all
          ),
          null: false
    end

    create unique_index(:predisclosure_list_subscribers, [:list_id, :user_id],
             name: "predisclosure_list_subscribers_unique_list_user_index"
           )
  end

  def down do
    drop constraint(
           :predisclosure_list_subscribers,
           "predisclosure_list_subscribers_user_id_fkey"
         )

    drop constraint(
           :predisclosure_list_subscribers,
           "predisclosure_list_subscribers_list_id_fkey"
         )

    drop_if_exists unique_index(:predisclosure_list_subscribers, [:list_id, :user_id],
                     name: "predisclosure_list_subscribers_unique_list_user_index"
                   )

    drop table(:predisclosure_list_subscribers)

    drop table(:predisclosure_list_members_versions)

    drop constraint(:predisclosure_list_members, "predisclosure_list_members_case_id_fkey")

    drop constraint(:predisclosure_list_members, "predisclosure_list_members_list_id_fkey")

    drop_if_exists unique_index(:predisclosure_list_members, [:list_id, :case_id],
                     name: "predisclosure_list_members_unique_list_case_index"
                   )

    drop table(:predisclosure_list_members)

    drop table(:predisclosure_lists_versions)

    drop_if_exists unique_index(:predisclosure_lists, [:name],
                     name: "predisclosure_lists_unique_name_index"
                   )

    drop table(:predisclosure_lists)

    drop table(:predisclosure_list_subscribers_versions)
  end
end
