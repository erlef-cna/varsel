defmodule Varsel.Repo.Migrations.AddCasePlannedDisclosure do
  @moduledoc """
  Adds the planned disclosure date of a case, and the date the last overdue
  reminder was sent for.
  """

  use Ecto.Migration

  def up do
    alter table(:cases) do
      add :planned_disclosure_at, :utc_datetime
      add :disclosure_reminded_for, :utc_datetime
    end
  end

  def down do
    alter table(:cases) do
      remove :disclosure_reminded_for
      remove :planned_disclosure_at
    end
  end
end
