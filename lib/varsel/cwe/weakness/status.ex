# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CWE.Weakness.Status do
  @moduledoc false
  use Ash.Type.Enum, values: [:stable, :draft, :incomplete, :deprecated, :obsolete]
end
