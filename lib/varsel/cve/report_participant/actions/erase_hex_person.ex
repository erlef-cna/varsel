# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CVE.ReportParticipant.Actions.EraseHexPerson do
  @moduledoc """
  Clears the name and address hex.pm gave us for someone it has since erased.
  """

  use Ash.Resource.Actions.Implementation

  alias Varsel.CVE

  @impl Ash.Resource.Actions.Implementation
  def run(input, _opts, context) do
    opts = Ash.Context.to_opts(context)

    input.arguments.username
    |> CVE.query_to_list_report_participants_for_hex_erasure(input.arguments[:email], opts)
    |> CVE.erase_report_participant!(
      Keyword.put(opts, :bulk_options,
        strategy: :stream,
        allow_stream_with: :full_read,
        notify?: true
      )
    )

    :ok
  end
end
