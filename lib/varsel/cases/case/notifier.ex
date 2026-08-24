# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Case.Notifier do
  @moduledoc """
  Ash notifier attached to `Varsel.CVE.CveRecord` that completes the case
  publish handoff as soon as the backing record reaches MITRE, instead of
  waiting for the 15-minute scheduler.

  Runs after the transaction commits and only enqueues the `:mark_published`
  Oban trigger; the job re-checks the trigger condition (case `:publishing`,
  record `:published`), so spurious notifications are cheap no-ops.
  """

  use Ash.Notifier

  alias Varsel.Cases.Case

  @impl Ash.Notifier
  def load(_resource, _action), do: [case: [:state]]

  @impl Ash.Notifier
  def notify(%Ash.Notifier.Notification{data: %{state: :published, case: %Case{state: :publishing} = case_record}}) do
    AshOban.run_trigger(case_record, :mark_published)

    :ok
  end

  def notify(_notification), do: :ok
end
