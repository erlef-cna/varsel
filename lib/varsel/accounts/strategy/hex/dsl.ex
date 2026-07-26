# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Accounts.Strategy.Hex.Dsl do
  @moduledoc false

  alias AshAuthentication.Strategy.Custom
  alias AshAuthentication.Strategy.OAuth2
  alias Varsel.Accounts.Assent.Hex

  @doc false
  @spec dsl :: Custom.entity()
  def dsl do
    OAuth2.dsl()
    |> Map.merge(%{
      name: :hex,
      args: [{:optional, :name, :hex}],
      describe: """
      Authentication strategy for [Hex.pm](https://hex.pm).

      Built on the `:oauth2` strategy, so every option it accepts is available
      here too. `base_url` has no default because hex.pm is self-hostable.
      """,
      auto_set_fields: [icon: :oauth2, assent_strategy: Hex]
    })
    |> Custom.set_defaults(Hex.default_config([]))
    # A matching email must never attach a hex sign-in to an existing account.
    # `trust_email_verified?` is the *only* switch that would enable that, so
    # it stays false; linking hex to an account happens from an authenticated
    # session, never from an email match.
    |> Custom.set_defaults(trust_email_verified?: false, on_untrusted_email_match: :reject)
  end
end
