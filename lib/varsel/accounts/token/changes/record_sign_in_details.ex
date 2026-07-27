# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Accounts.Token.Changes.RecordSignInDetails do
  @moduledoc """
  Notes the browser and address a session was signed in from, so the account
  page can tell one session from another.

  `VarselWeb.Plugs.SignInDetails` puts them in the context; this writes them.
  Sessions only — the same resource also holds password resets and
  confirmations, and where those came from is nothing the page shows.
  """

  use Ash.Resource.Change

  @impl Ash.Resource.Change
  def change(changeset, _opts, context) do
    with "user" <- Ash.Changeset.get_attribute(changeset, :purpose),
         %{} = details <- get_in(context.source_context, [:shared, :sign_in_details]) do
      Ash.Changeset.force_change_attribute(changeset, :extra_data, details)
    else
      _not_a_session -> changeset
    end
  end
end
