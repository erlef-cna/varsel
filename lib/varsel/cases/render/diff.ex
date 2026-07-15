# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Render.Diff do
  @moduledoc """
  Line-based diff between two CNA containers, for the "what will this
  amendment change at MITRE" view.

  Both containers are serialized to pretty JSON with recursively sorted keys
  (map key order is otherwise arbitrary), then diffed line-wise with
  `List.myers_difference/2`. Long unchanged runs collapse to their edges so
  the changes stay readable.
  """

  @context_lines 3
  @collapse_threshold 8

  @type line :: {:eq | :del | :ins, String.t()} | {:skip, pos_integer()}

  @doc """
  Display lines of the diff from `old` to `new`: `{:del, line}` / `{:ins,
  line}` / `{:eq, line}` entries with `{:skip, n}` markers replacing the
  middle of unchanged runs longer than #{@collapse_threshold} lines.
  """
  @spec lines(map(), map()) :: [line()]
  def lines(old, new) do
    old_lines = old |> stable_json() |> String.split("\n")
    new_lines = new |> stable_json() |> String.split("\n")

    old_lines
    |> List.myers_difference(new_lines)
    |> Enum.flat_map(fn
      {:eq, lines} -> collapse(lines)
      {:del, lines} -> Enum.map(lines, &{:del, &1})
      {:ins, lines} -> Enum.map(lines, &{:ins, &1})
    end)
  end

  @doc "True when the diff contains any change."
  @spec changed?([line()]) :: boolean()
  def changed?(lines), do: Enum.any?(lines, &match?({kind, _} when kind in [:del, :ins], &1))

  @doc "Pretty JSON with recursively sorted object keys (stable across runs)."
  @spec stable_json(term()) :: String.t()
  def stable_json(term) do
    term |> stable() |> Jason.encode!(pretty: true)
  end

  defp stable(map) when is_map(map) do
    %Jason.OrderedObject{
      values: map |> Enum.map(fn {key, value} -> {key, stable(value)} end) |> Enum.sort_by(&elem(&1, 0))
    }
  end

  defp stable(list) when is_list(list), do: Enum.map(list, &stable/1)
  defp stable(other), do: other

  defp collapse(lines) when length(lines) <= @collapse_threshold do
    Enum.map(lines, &{:eq, &1})
  end

  defp collapse(lines) do
    head = Enum.take(lines, @context_lines)
    tail = Enum.take(lines, -@context_lines)
    skipped = length(lines) - 2 * @context_lines

    Enum.map(head, &{:eq, &1}) ++ [{:skip, skipped}] ++ Enum.map(tail, &{:eq, &1})
  end
end
