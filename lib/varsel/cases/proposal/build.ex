# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Proposal.Build do
  @moduledoc """
  Turns the case workspace's edited form params into `Varsel.Cases.Proposal`
  attribute maps.

  In suggest mode an edit does not change the case: it records a field-level
  change request against it, for someone else to accept or decline. This
  module is the translation step — form params in, proposal attributes out —
  and creates nothing itself; the caller passes the maps to
  `Varsel.Cases.create_case_proposal/2` with an actor.

  Params are diffed against the *projection* (the case with all open
  proposals applied), never the stored case, so untouched proposed values
  produce no proposal and a changed one links back as a counter-proposal via
  `parent_proposal_id`. Comparison is deliberately loose (`changed_value?/2`)
  because form params arrive as strings while the stored side holds atoms,
  integers and structs.
  """

  alias Varsel.Cases.AffectedPackage.Preset
  alias Varsel.Cases.AffectedPackage.ProgramFile
  alias Varsel.Cases.Projection
  alias Varsel.Cases.Proposable
  alias Varsel.Types.CVSS

  @typedoc "Attributes for one `Varsel.Cases.create_case_proposal/2` call."
  @type attrs :: %{required(atom()) => term()}

  @doc """
  One `:set` proposal per case field whose param differs from the projected
  case. `display_case` is the projected case the form was rendered from.
  """
  @spec content_proposals(
          case_id :: Ash.UUID.t(),
          display_case :: struct(),
          projection :: Projection.t() | nil,
          params :: map(),
          reasoning :: String.t() | nil
        ) :: [attrs()]
  def content_proposals(case_id, display_case, projection, params, reasoning) do
    for field <- Proposable.fields(Varsel.Cases.Case),
        key = to_string(field),
        Map.has_key?(params, key),
        changed_value?(Map.get(display_case, field), params[key]) do
      %{
        case_id: case_id,
        target: :case,
        operation: :set,
        field_name: key,
        proposed_value: %{"value" => params[key]},
        reasoning: reasoning,
        parent_proposal_id: countered_id(projection, :case, nil, key)
      }
    end
  end

  @doc """
  A single `:insert` proposal carrying the new row's payload.

  `config` is the workspace's child registry entry (`:resource`, `:target`
  and, for the well-known-product presets, `:preset`). A preset contributes
  its own payload field list and rides along in the payload so accepting the
  proposal replays the same preset action that direct creation would.
  """
  @spec insert_proposals(
          config :: map(),
          case_id :: Ash.UUID.t(),
          params :: map(),
          reasoning :: String.t() | nil
        ) :: [attrs()]
  def insert_proposals(config, case_id, params, reasoning) do
    allowed =
      case config[:preset] do
        nil ->
          Proposable.fields(config.resource) ++ Proposable.insert_extra_fields(config.resource)

        preset ->
          Preset.payload_fields(preset)
      end

    payload =
      params
      |> Map.take(Enum.map(allowed, &to_string/1))
      |> Enum.reject(fn {_key, value} -> value in [nil, "", []] end)
      |> Map.new()

    payload =
      case config[:preset] do
        nil -> payload
        preset -> Map.put(payload, "preset", to_string(preset))
      end

    [
      %{
        case_id: case_id,
        target: config.target,
        operation: :insert,
        target_id: params["affected_package_id"],
        proposed_value: %{"value" => payload},
        reasoning: reasoning
      }
    ]
  end

  @doc """
  One `:set` proposal per changed field of an existing child row.

  `row` is the projected row the edit form was built from, so the diff yields
  only genuinely new changes; counters link to the countered proposal.
  """
  @spec set_proposals(
          config :: map(),
          case_id :: Ash.UUID.t(),
          row :: struct(),
          projection :: Projection.t() | nil,
          params :: map(),
          reasoning :: String.t() | nil
        ) :: [attrs()]
  def set_proposals(config, case_id, row, projection, params, reasoning) do
    for field <- Proposable.set_fields(config.resource),
        key = to_string(field),
        Map.has_key?(params, key),
        changed_value?(Map.get(row, field), params[key]) do
      %{
        case_id: case_id,
        target: config.target,
        operation: :set,
        target_id: row.id,
        field_name: key,
        proposed_value: %{"value" => params[key]},
        reasoning: reasoning,
        parent_proposal_id: countered_id(projection, config.target, row.id, key)
      }
    end
  end

  @doc """
  Loose equality between a stored value and its form-param representation
  (enum atoms vs strings, integers vs digits, CVSS structs vs vectors, nil vs
  empty input).
  """
  @spec changed_value?(current :: term(), param :: term()) :: boolean()
  def changed_value?(current, param), do: comparable(current) != comparable(param)

  # The id of the open :set proposal this change would counter, if any.
  defp countered_id(nil, _target, _target_id, _field), do: nil

  defp countered_id(projection, target, target_id, field) do
    case Projection.countered(projection, target, target_id, field) do
      nil -> nil
      proposal -> proposal.id
    end
  end

  defp comparable(%CVSS{vector: vector}), do: vector

  defp comparable(%ProgramFile{} = file) do
    %{"path" => file.path, "modules" => file.modules, "routines" => file.routines}
  end

  defp comparable(nil), do: ""
  defp comparable(value) when is_list(value), do: Enum.map(value, &comparable/1)
  defp comparable(value) when is_map(value), do: value
  defp comparable(value), do: to_string(value)
end
