# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Proposal.Changes.PackProposal do
  @moduledoc """
  Backs the specialized `propose_*` create actions. Each of those actions
  declares its own typed arguments (the exact payload of one target/operation);
  this change packs those arguments into the generic proposal shape
  (`target`, `operation`, `field_name`, `proposed_value` envelope) that the
  private `:propose` action's storage and `ValidTarget` validation already
  understand.

  This is the single place the specialized actions share, so adding a new
  `propose_*` action is just an `accept`/`argument` list plus one
  `change {PackProposal, target: ..., operation: ...}` line — no duplicated
  validation, storage, or envelope-building.

  Options:
    * `:target` — the proposal target atom (`:credit`, `:reference`, `:case`, ...).
      Required except for `:delete`, whose target varies at runtime and is
      carried by the action's accepted `:target` attribute instead.
    * `:operation` (required) — `:set`, `:insert`, or `:delete`.
    * `:field` — for `:set`, the fixed `field_name` this action edits (e.g.
      `:description_md`). The value is taken from the action's `value` argument.
    * `:preset` — for an `affected_package` `:insert`, injects a fixed
      `"preset"` key (`:otp` / `:elixir` / `:gleam`) into the payload so
      `ValidTarget` routes to preset validation. The preset is implied by the
      action, so it is a constant here rather than a caller-supplied argument.

  For `:set` the action carries a single `value` argument; for `:insert` the
  action's arguments (minus bookkeeping) become the payload map; for `:delete`
  no payload is packed (the row is addressed by `target_id`).
  """

  use Ash.Resource.Change

  alias Ash.Resource.Change

  @operations [:set, :insert, :delete]
  @presets [:otp, :elixir, :gleam]

  @impl Change
  def init(opts) do
    cond do
      is_nil(opts[:target]) and opts[:operation] != :delete ->
        {:error, "target is required"}

      opts[:operation] not in @operations ->
        {:error, "operation must be one of #{inspect(@operations)}"}

      opts[:operation] == :set and is_nil(opts[:field]) ->
        {:error, ":set proposals require a :field option"}

      not is_nil(opts[:preset]) and opts[:preset] not in @presets ->
        {:error, "preset must be one of #{inspect(@presets)}"}

      true ->
        {:ok, opts}
    end
  end

  @impl Change
  def change(changeset, opts, _context) do
    changeset
    |> force_target(opts[:target])
    |> Ash.Changeset.force_change_attribute(:operation, opts[:operation])
    |> pack(opts[:operation], opts)
  end

  # A fixed-target action stamps its target; :delete leaves the accepted
  # `:target` attribute (chosen at runtime) untouched.
  defp force_target(changeset, nil), do: changeset

  defp force_target(changeset, target), do: Ash.Changeset.force_change_attribute(changeset, :target, target)

  defp pack(changeset, :set, opts) do
    value = jsonify(changeset, :value)

    changeset
    |> Ash.Changeset.force_change_attribute(:field_name, to_string(opts[:field]))
    |> Ash.Changeset.force_change_attribute(:proposed_value, %{"value" => value})
  end

  defp pack(changeset, :insert, opts) do
    Ash.Changeset.force_change_attribute(changeset, :proposed_value, %{
      "value" => changeset |> payload() |> with_preset(opts[:preset])
    })
  end

  defp pack(changeset, :delete, _opts), do: changeset

  defp with_preset(payload, nil), do: payload
  defp with_preset(payload, preset), do: Map.put(payload, "preset", to_string(preset))

  # The payload is the action's own arguments, minus the ones that address the
  # proposal rather than describe the row. String keys to match the envelope
  # ValidTarget expects.
  @bookkeeping_args [:case_id, :target_id, :reasoning, :parent_proposal_id, :value]

  defp payload(changeset) do
    changeset.action.arguments
    |> Enum.map(& &1.name)
    |> Enum.reject(&(&1 in @bookkeeping_args))
    |> Enum.reduce(%{}, fn arg, acc ->
      case Ash.Changeset.fetch_argument(changeset, arg) do
        {:ok, nil} -> acc
        {:ok, _value} -> Map.put(acc, to_string(arg), jsonify(changeset, arg))
        :error -> acc
      end
    end)
  end

  # The typed argument casts inputs into rich Ash values (a CVSS struct, an
  # embedded TimelineEntry, an enum atom); the generic proposal stores its
  # envelope as plain JSON that `ValidTarget` and the apply actions re-cast.
  # Dump each value back through its argument type so the stored shape matches
  # what those consumers expect — never a struct the JSONB column can't encode.
  defp jsonify(changeset, name) do
    argument = Enum.find(changeset.action.arguments, &(&1.name == name))
    value = Ash.Changeset.get_argument(changeset, name)

    case Ash.Type.dump_to_embedded(argument.type, value, argument.constraints || []) do
      {:ok, dumped} -> dumped
      _error -> value
    end
  end
end
