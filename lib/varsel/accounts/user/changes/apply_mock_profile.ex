# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

if Application.compile_env(:varsel, :mock_login_enabled?, false) do
  defmodule Varsel.Accounts.User.Changes.ApplyMockProfile do
    @moduledoc """
    Fills in a mock user's profile from the role it is signing in as.

    The synthetic `github_id` is derived from the role so that repeated mock
    sign-ins upsert the same row instead of piling up dummy users.
    """

    use Ash.Resource.Change

    @impl Ash.Resource.Change
    def change(changeset, _opts, _context) do
      slug =
        case Ash.Changeset.get_attribute(changeset, :role) do
          nil -> "no-role"
          role -> to_string(role)
        end

      changeset
      |> Ash.Changeset.force_change_attribute(:github_id, "mock-#{slug}")
      |> Ash.Changeset.force_change_attribute(:github_handle, "mock-#{slug}")
      |> Ash.Changeset.force_change_attribute(:name, "Mock #{label(slug)}")
      |> Ash.Changeset.force_change_attribute(:email, "mock-#{slug}@example.com")
    end

    defp label(slug), do: slug |> String.replace("-", " ") |> String.capitalize()
  end
end
