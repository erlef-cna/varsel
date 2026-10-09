defmodule Varsel.Repo.Migrations.DropNamesFromParticipantVersions do
  use Ecto.Migration

  def up do
    execute """
    UPDATE report_participants_versions
    SET changes = changes - 'name'
    WHERE changes ? 'name'
    """
  end

  def down, do: :ok
end
