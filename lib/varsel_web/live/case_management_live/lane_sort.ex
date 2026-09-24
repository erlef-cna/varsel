# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.CaseManagementLive.LaneSort do
  @moduledoc """
  How the pipeline board orders the cards inside each lane.

  The order rides in the URL (`?sort=`) so it survives a reload and the back
  button, which is what makes it worth keeping at all: a board you re-sort on
  every visit is a board you fight.
  """

  @default :newest

  @orders [
    newest: %{label: "Newest first", key: :updated_at, direction: :desc},
    oldest: %{label: "Oldest first", key: :updated_at, direction: :asc},
    severity: %{label: "Severity", key: :cvss_score, direction: :desc},
    title: %{label: "Title", key: :title, direction: :asc}
  ]

  @doc "The order applied when the URL names none, or names one that does not exist."
  @spec default() :: atom()
  def default, do: @default

  @doc "Every order, as `{value, label}` pairs in menu order."
  @spec options() :: [{atom(), String.t()}]
  def options, do: Enum.map(@orders, fn {value, %{label: label}} -> {value, label} end)

  @doc "The label of one order."
  @spec label(atom()) :: String.t()
  def label(order), do: @orders |> Keyword.fetch!(order) |> Map.fetch!(:label)

  @doc """
  Resolves a `?sort=` parameter to an order.

  An unknown or absent value takes the default, so a hand-edited URL renders a
  board rather than an error.
  """
  @spec parse(String.t() | nil) :: atom()
  def parse(param) when is_binary(param) do
    case Enum.find(@orders, fn {value, _spec} -> Atom.to_string(value) == param end) do
      {value, _spec} -> value
      nil -> @default
    end
  end

  def parse(_param), do: @default

  @doc "The `?sort=` value for a URL, or nil for the default, which is left off."
  @spec param(atom()) :: String.t() | nil
  def param(@default), do: nil
  def param(order), do: Atom.to_string(order)

  @doc """
  Sorts one lane's cards.

  Ties break on `updated_at` descending, so an order that leaves rows equal —
  every unscored case under `:severity` — still reads newest-first rather than
  in whatever order the rows arrived.
  """
  @spec sort([map()], atom()) :: [map()]
  def sort(cards, order) do
    %{key: key, direction: direction} = Keyword.fetch!(@orders, order)

    Enum.sort_by(cards, &sort_key(&1, key, direction), &compare/2)
  end

  defp sort_key(card, key, direction), do: {direction, Map.get(card, key), card.updated_at}

  # A nil sorts last whichever way the column runs: an unscored case is not the
  # most severe, and an untitled one is not first alphabetically.
  defp compare({direction, nil, left_tie}, {direction, nil, right_tie}), do: newest_first(left_tie, right_tie)

  defp compare({_left_direction, nil, _left_tie}, {_right_direction, _right, _right_tie}), do: false

  defp compare({_left_direction, _left, _left_tie}, {_right_direction, nil, _right_tie}), do: true

  defp compare({direction, same, left_tie}, {direction, same, right_tie}), do: newest_first(left_tie, right_tie)

  defp compare({:asc, left, _left_tie}, {:asc, right, _right_tie}), do: before?(left, right)
  defp compare({:desc, left, _left_tie}, {:desc, right, _right_tie}), do: before?(right, left)

  defp newest_first(left, right), do: DateTime.compare(left, right) != :lt

  defp before?(%DateTime{} = left, %DateTime{} = right), do: DateTime.compare(left, right) != :gt

  defp before?(left, right) when is_binary(left) and is_binary(right), do: String.downcase(left) <= String.downcase(right)

  defp before?(left, right), do: left <= right
end
