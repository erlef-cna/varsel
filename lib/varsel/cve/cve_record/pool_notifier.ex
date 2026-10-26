# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CVE.CveRecord.PoolNotifier do
  @moduledoc """
  Ash notifier attached to `Varsel.CVE.CveRecord` that refills the open pool
  as soon as an ID leaves it, instead of waiting for the 15-minute schedule.
  A burst of assignments would otherwise drain the pool between two runs.

  Runs after the transaction commits and only enqueues the `:top_up_pool`
  job. The job counts the pool itself, so it reserves nothing while the pool
  still meets its minimum size.
  """

  use Ash.Notifier

  alias Varsel.CVE.CveRecord

  @impl Ash.Notifier
  def notify(%Ash.Notifier.Notification{action: %{name: :assign}}) do
    AshOban.schedule(CveRecord, :top_up_pool)

    :ok
  end

  def notify(_notification), do: :ok
end
