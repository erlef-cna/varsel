# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CVE.OsvRecord.Notifier do
  @moduledoc """
  Ash notifier attached to `CveRecord` that nudges the OSV lifecycle as soon
  as a CVE record changes, instead of waiting for the 15-minute schedulers.

  Runs after the transaction commits and only enqueues Oban jobs — the jobs
  re-check the `:sync` trigger condition (respectively the `:create_missing`
  anti-join), so notifications for changes without OSV impact are cheap
  no-ops. States that can not have OSV impact are skipped outright.
  """

  use Ash.Notifier

  alias Ash.Notifier.Notification
  alias Varsel.CVE.OsvRecord

  @impl Ash.Notifier
  def load(_resource, _action), do: [:osv_record]

  @impl Ash.Notifier
  def notify(%Notification{data: %{state: state, osv_record: %OsvRecord{} = osv_record}})
      when state in [:published, :rejected] do
    AshOban.run_trigger(osv_record, :sync)

    :ok
  end

  def notify(%Notification{data: %{state: :published}}) do
    AshOban.schedule(OsvRecord, :create_missing)

    :ok
  end

  def notify(_notification), do: :ok
end
