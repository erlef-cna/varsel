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

  alias Varsel.CVE.OsvRecord

  @impl Ash.Notifier
  def notify(%Ash.Notifier.Notification{data: %{state: state} = record}) when state in [:published, :rejected] do
    record = Ash.load!(record, :osv_record, authorize?: false)

    cond do
      record.osv_record ->
        AshOban.run_trigger(record.osv_record, :sync)

      state == :published ->
        AshOban.schedule(OsvRecord, :create_missing)

      true ->
        :ok
    end

    :ok
  end

  def notify(_notification), do: :ok
end
