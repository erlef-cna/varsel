# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Case.Aggregates.ConcatVectors do
  @moduledoc """
  Concatenates a relationship's search vectors into one, so a parent ranks
  against everything its children carry.

  Postgres concatenates two `tsvector`s but ships no aggregate over a set of
  them, so the `cases` migration creates `tsvector_concat_agg`.

  A parent with no children aggregates to NULL. Callers coalesce the result.
  """

  use AshPostgres.CustomAggregate

  require Ecto.Query

  @impl AshPostgres.CustomAggregate
  def dynamic(opts, binding) do
    Ecto.Query.dynamic(
      [],
      fragment("tsvector_concat_agg(?)", field(as(^binding), ^opts[:field]))
    )
  end
end
