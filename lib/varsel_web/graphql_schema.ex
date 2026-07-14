# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.GraphqlSchema do
  @moduledoc false
  use Absinthe.Schema

  use AshGraphql,
    domains: [
      Varsel.Accounts,
      Varsel.CAPEC,
      Varsel.Cases,
      Varsel.CVE,
      Varsel.CWE
    ]

  import_types Absinthe.Plug.Types

  query do
    # Custom Absinthe queries can be placed here
  end

  mutation do
    # Custom Absinthe mutations can be placed here
  end

  subscription do
    # Custom Absinthe subscriptions can be placed here
  end
end
