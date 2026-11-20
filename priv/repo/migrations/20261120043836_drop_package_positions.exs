defmodule Varsel.Repo.Migrations.DropPackagePositions do
  @moduledoc """
  Drops the hand-set positions of affected packages and their channels.
  Packages and channels now sort by what they are.
  """

  use Ecto.Migration

  def up do
    alter table(:case_package_channels) do
      remove :position
    end

    alter table(:case_affected_packages) do
      remove :position
    end
  end

  def down do
    alter table(:case_affected_packages) do
      add :position, :bigint, null: false, default: 0
    end

    alter table(:case_package_channels) do
      add :position, :bigint, null: false, default: 0
    end
  end
end
