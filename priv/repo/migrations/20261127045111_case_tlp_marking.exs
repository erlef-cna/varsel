defmodule Varsel.Repo.Migrations.CaseTlpMarking do
  @moduledoc """
  Turns the TLP label of a case into a marking: the label and an optional
  caveat, in one jsonb value.
  """

  use Ecto.Migration

  def up do
    execute "ALTER TABLE cases ALTER COLUMN tlp DROP DEFAULT"
    execute "ALTER TABLE cases ALTER COLUMN tlp TYPE jsonb USING jsonb_build_object('label', tlp)"
  end

  def down do
    execute "ALTER TABLE cases ALTER COLUMN tlp TYPE text USING tlp->>'label'"
    execute "ALTER TABLE cases ALTER COLUMN tlp SET DEFAULT 'red'"
  end
end
