# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.CaseInvite.Changes.CanonicalizeUsername do
  @moduledoc """
  Confirms an invited handle at its provider and stores the spelling it gave
  back.

  An unconfirmed handle would become an invite nobody can claim, so a provider
  that cannot be reached fails the invite too.
  """

  use Ash.Resource.Change

  alias Ash.Resource.Change
  alias Varsel.Accounts.GitHub
  alias Varsel.HexPm

  @impl Change
  def change(changeset, _opts, _context) do
    strategy = Ash.Changeset.get_attribute(changeset, :strategy)
    username = changeset |> Ash.Changeset.get_attribute(:username) |> to_string() |> String.trim()

    case confirm(strategy, username) do
      {:ok, canonical} ->
        Ash.Changeset.change_attribute(changeset, :username, canonical)

      {:error, message} ->
        Ash.Changeset.add_error(changeset, field: :username, message: message)
    end
  end

  defp confirm(_strategy, ""), do: {:error, "is required"}

  defp confirm(strategy, username) do
    case lookup(strategy, username) do
      {:ok, canonical} -> {:ok, canonical}
      :not_found -> {:error, "is not a #{provider_name(strategy)} account"}
    end
  end

  defp lookup(:github, username), do: GitHub.user(username)
  defp lookup(:hex, username), do: HexPm.user(username)

  defp provider_name(:github), do: "GitHub"
  defp provider_name(:hex), do: "hex.pm"
end
