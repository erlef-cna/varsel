# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.RowOrder do
  @moduledoc """
  Sort keys that order rows in memory the way PostgreSQL orders them: text by
  byte (`COLLATE "C"`), `NULL` after every value, timestamps by instant.

  The resources sort their relationships in the database. The same order has
  to hold for rows that never came from it, such as the phantom rows a
  projection adds for open proposals, so each resource's `sort/1` builds its
  key from these.
  """

  @doc "Text, nil last."
  @spec text(term()) :: {boolean(), String.t()}
  def text(nil), do: {true, ""}
  def text(value), do: {false, to_string(value)}

  @doc "Text compared without case, nil last."
  @spec ci(term()) :: {boolean(), String.t()}
  def ci(nil), do: {true, ""}
  def ci(value), do: {false, value |> to_string() |> String.downcase()}

  @doc "A timestamp, nil last."
  @spec time(DateTime.t() | nil) :: {boolean(), integer()}
  def time(nil), do: {true, 0}
  def time(%DateTime{} = at), do: {false, DateTime.to_unix(at, :microsecond)}
end
