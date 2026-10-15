# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.CaseAssignment.Changes.ClaimInvites do
  @moduledoc """
  Turns the invites naming a handle into assignments, for the sign-in that
  proved the account owns it.

  Each invite becomes an assignment on its own case, carrying its note, and
  is then withdrawn. A handle with no invites waiting does nothing.
  """

  use Ash.Resource.Actions.Implementation

  alias Varsel.Cases

  @impl Ash.Resource.Actions.Implementation
  def run(input, _opts, context) do
    signal = input.arguments.signal

    # `signal_path` rides on the action input, not the implementation context,
    # and `Ash.Context.to_opts/1` does not carry it. The policies of
    # everything this calls are written against it.
    opts = Keyword.put(Ash.Context.to_opts(context), :context, input.context)

    signal.strategy
    |> Cases.list_case_invites_for_identity!(signal.username, opts)
    |> Enum.each(&claim(&1, signal.user_id, opts))

    :ok
  end

  defp claim(invite, user_id, opts) do
    Cases.assign_case_user!(
      %{case_id: invite.case_id, user_id: user_id, note: invite.note},
      opts
    )

    Cases.withdraw_case_invite!(invite, opts)
  end
end
