# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CWE.View.Type do
  @moduledoc false
  use Ash.Type.Enum, values: [:graph, :explicit_slice, :implicit_slice]
end
