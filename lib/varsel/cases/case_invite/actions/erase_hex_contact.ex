# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.CaseInvite.Actions.EraseHexContact do
  @moduledoc """
  Clears the address on every hex.pm invite naming someone hex.pm has since
  erased.
  """

  use Ash.Resource.Actions.Implementation

  alias Varsel.Cases

  @impl Ash.Resource.Actions.Implementation
  def run(input, _opts, context) do
    opts = Ash.Context.to_opts(context)

    input.arguments.username
    |> Cases.query_to_list_case_invites_for_hex_erasure(input.arguments[:email], opts)
    |> Cases.erase_case_invite_email!(
      Keyword.put(opts, :bulk_options,
        strategy: :stream,
        allow_stream_with: :full_read,
        notify?: true
      )
    )

    :ok
  end
end
