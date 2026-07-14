# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CVE.CveValidation.Source do
  @moduledoc false
  use Ash.Type.Enum, values: [:schema, :cvelint, :hex]
end
