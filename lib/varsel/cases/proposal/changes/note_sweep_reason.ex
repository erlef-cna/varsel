# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Proposal.Changes.NoteSweepReason do
  @moduledoc """
  Fills in the resolution note of a proposal swept by a signal, for the
  signals that resolve proposals without a caller to explain why.

  A caller-supplied note wins, so the hand-rolled sweeps keep the reasons
  they pass.
  """

  use Ash.Resource.Change

  alias Varsel.Cases.Signals

  @notes %{
    {Signals, :case_closed} => "the case was closed",
    {Signals, :proposal_accepted} => "a competing proposal was accepted",
    {Signals, :proposal_target_destroyed} => "the targeted row was deleted"
  }

  @impl Ash.Resource.Change
  def change(changeset, _opts, _context) do
    case {Ash.Changeset.get_attribute(changeset, :resolution_note), signal(changeset)} do
      {nil, {_module, _signal} = key} when is_map_key(@notes, key) ->
        Ash.Changeset.force_change_attribute(changeset, :resolution_note, @notes[key])

      _other ->
        changeset
    end
  end

  defp signal(%{context: %{signal_path: [%{signal_module: module, signal: signal} | _]}}), do: {module, signal}

  defp signal(_changeset), do: nil
end
