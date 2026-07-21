defmodule Varsel.Repo.Migrations.RestructureProgramFiles do
  @moduledoc """
  Restructures affected-package program data: the flat `program_files` /
  `modules` / `program_routines` text arrays become one `program_files`
  jsonb[] of `{path, modules, routines}` objects, so rendering can scope
  files (and the modules/routines they contribute) per channel.

  Hand-tuned from the generated migration: Postgres cannot cast text[] to
  jsonb[] in place, and the old data is worth converting — single-file
  packages keep their modules/routines attached to that file; multi-file
  packages keep the paths (the old model never said which file contributed
  which module).
  """

  use Ecto.Migration

  def up do
    alter table(:case_affected_packages) do
      add :program_files_new, {:array, :map}, null: false, default: []
    end

    execute """
    UPDATE case_affected_packages
    SET program_files_new = CASE
      WHEN coalesce(array_length(program_files, 1), 0) = 1 THEN
        ARRAY[jsonb_build_object(
          'path', program_files[1],
          'modules', to_jsonb(modules),
          'routines', to_jsonb(program_routines)
        )]
      ELSE
        ARRAY(
          SELECT jsonb_build_object('path', p, 'modules', '[]'::jsonb, 'routines', '[]'::jsonb)
          FROM unnest(program_files) AS p
        )
    END
    """

    alter table(:case_affected_packages) do
      remove :program_files
      remove :modules
      remove :program_routines
    end

    rename table(:case_affected_packages), :program_files_new, to: :program_files
  end

  def down do
    alter table(:case_affected_packages) do
      add :program_files_old, {:array, :text}, null: false, default: []
      add :modules, {:array, :text}, null: false, default: []
      add :program_routines, {:array, :text}, null: false, default: []
    end

    execute """
    UPDATE case_affected_packages
    SET program_files_old = ARRAY(SELECT f ->> 'path' FROM unnest(program_files) AS f),
        modules = ARRAY(
          SELECT DISTINCT m
          FROM unnest(program_files) AS f, jsonb_array_elements_text(f -> 'modules') AS m
        ),
        program_routines = ARRAY(
          SELECT DISTINCT r
          FROM unnest(program_files) AS f, jsonb_array_elements_text(f -> 'routines') AS r
        )
    """

    alter table(:case_affected_packages) do
      remove :program_files
    end

    rename table(:case_affected_packages), :program_files_old, to: :program_files
  end
end
