# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Types.TSVector do
  @moduledoc """
  A Postgres `tsvector`.
  """

  use Ash.Type

  @impl Ash.Type
  def storage_type(_constraints), do: :tsvector

  @impl Ash.Type
  def cast_input(value, _constraints), do: {:ok, value}

  @impl Ash.Type
  def cast_stored(value, _constraints), do: {:ok, value}

  @impl Ash.Type
  def dump_to_native(value, _constraints), do: {:ok, value}
end
