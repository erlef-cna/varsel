# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Types.OkResult do
  @moduledoc """
  Return type for generic actions whose only result is that they ran.
  """

  use Ash.Type.Enum, values: [:ok]
end
