defmodule Varsel.Repo.Migrations.AddCaseTlp do
  @moduledoc """
  Adds the TLP label to cases. A case that was published once is public, so it
  starts at TLP:CLEAR. Every other case starts at TLP:RED.
  """

  use Ecto.Migration

  def up do
    alter table(:cases) do
      add :tlp, :text, null: false, default: "red"
    end

    execute "UPDATE cases SET tlp = 'clear' WHERE published_at IS NOT NULL"
  end

  def down do
    alter table(:cases) do
      remove :tlp
    end
  end
end
