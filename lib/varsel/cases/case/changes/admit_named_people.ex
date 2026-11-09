# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Case.Changes.AdmitNamedPeople do
  @moduledoc """
  Turns the people an intake named by handle into the `:assignments` and
  `:invites` the case is created with: an assignment for a handle someone
  here owns, an invite for any other.
  """

  use Ash.Resource.Change

  alias Ash.Changeset
  alias Varsel.Accounts

  @impl Ash.Resource.Change
  def change(changeset, _opts, _context) do
    {assignments, invites} =
      changeset
      |> Changeset.get_argument(:people)
      |> List.wrap()
      |> Enum.uniq_by(&{&1.strategy, String.downcase(&1.username)})
      |> Enum.reduce({[], []}, &admit/2)

    changeset
    |> Changeset.set_argument(
      :assignments,
      Enum.uniq_by(
        List.wrap(Changeset.get_argument(changeset, :assignments)) ++ assignments,
        & &1.user_id
      )
    )
    |> Changeset.set_argument(:invites, invites)
  end

  defp admit(person, {assignments, invites}) do
    case Accounts.get_identity_for_handle(to_string(person.strategy), person.username,
           actor: Varsel.Service.identity_claim()
         ) do
      {:ok, %{user_id: user_id}} ->
        {assignments ++ [%{user_id: user_id, note: person[:note]}], invites}

      _no_owner ->
        invite = %{
          strategy: person.strategy,
          username: person.username,
          email: person[:email],
          email_optional: true,
          note: person[:note],
          role: person[:role] || :other
        }

        {assignments, invites ++ [invite]}
    end
  end
end
