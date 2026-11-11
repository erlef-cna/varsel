# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.CaseManagementLive.PackageSort do
  @moduledoc """
  How the pipeline board orders its package rows.

  The order rides in the URL (`?packages=`), beside the order of the cases
  inside a row, so a board sorted both ways survives a reload and the back
  button.
  """

  @default :recent

  @orders [
    recent: "Latest update",
    oldest: "Oldest case",
    severity: "Highest severity",
    cases: "Most cases",
    name: "Name"
  ]

  @doc "The order applied when the URL names none, or names one that does not exist."
  @spec default() :: atom()
  def default, do: @default

  @doc "Every order, as `{value, label}` pairs in menu order."
  @spec options() :: [{atom(), String.t()}]
  def options, do: @orders

  @doc """
  Resolves a `?packages=` parameter to an order.

  An unknown or absent value takes the default, so a hand-edited URL renders a
  board rather than an error.
  """
  @spec parse(String.t() | nil) :: atom()
  def parse(param) when is_binary(param) do
    case Enum.find(@orders, fn {value, _label} -> Atom.to_string(value) == param end) do
      {value, _label} -> value
      nil -> @default
    end
  end

  def parse(_param), do: @default

  @doc "The `?packages=` value for a URL, or nil for the default, which is left off."
  @spec param(atom()) :: String.t() | nil
  def param(@default), do: nil
  def param(order), do: Atom.to_string(order)

  @doc """
  Sorts package rows.

  A row is a map of `label`, `total`, `opened_at` (when its oldest case was
  opened), `max_score` (nil when none of its cases is scored) and
  `updated_at` (its latest activity). Ties break on the name, so rows that
  are equal under an order keep a steady place.
  """
  @spec sort([map()], atom()) :: [map()]
  def sort(rows, order), do: Enum.sort_by(rows, &{rank(&1, order), String.downcase(&1.label)})

  defp rank(row, :cases), do: -row.total
  defp rank(_row, :name), do: 0
  defp rank(row, :oldest), do: DateTime.to_unix(row.opened_at, :microsecond)
  defp rank(%{max_score: nil}, :severity), do: 1.0
  defp rank(row, :severity), do: -row.max_score
  defp rank(row, :recent), do: -DateTime.to_unix(row.updated_at, :microsecond)
end
