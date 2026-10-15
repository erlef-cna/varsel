# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CVE.ReportParticipant.Changes.ClaimForIdentity do
  @moduledoc """
  Points the participants naming a handle at the account that just proved it
  owns it.

  A reporter's row is spent instead of linked, because the report's own
  `reporter` then holds everything the row was carrying. Every other row
  stays: it is the record of who an intake named, and the case assignment it
  becomes is made when a POC opens the case.
  """

  use Ash.Resource.Actions.Implementation

  alias Varsel.CVE

  @impl Ash.Resource.Actions.Implementation
  def run(input, _opts, context) do
    signal = input.arguments.signal

    # `signal_path` rides on the action input, not the implementation context,
    # and `Ash.Context.to_opts/1` does not carry it. The policies of
    # everything this calls are written against it.
    opts = Keyword.put(Ash.Context.to_opts(context), :context, input.context)

    signal.strategy
    |> CVE.list_report_participants_for_identity!(signal.username, opts)
    |> Enum.each(&claim(&1, signal.user_id, opts))
  end

  defp claim(%{role: :reporter} = participant, user_id, opts) do
    link_report(participant, user_id, opts)

    CVE.spend_report_participant!(participant, opts)
  end

  defp claim(participant, user_id, opts) do
    CVE.link_report_participant_user!(participant, %{user_id: user_id}, opts)
  end

  # Checked rather than rescued: this runs inside the sign-in transaction, so
  # a report that already found its reporter must not fail the login.
  defp link_report(participant, user_id, opts) do
    report = CVE.get_vulnerability_report!(participant.report_id, opts)

    if is_nil(report.reporter_id) do
      CVE.link_vulnerability_report_reporter!(report, %{reporter_id: user_id}, opts)
    end
  end
end
