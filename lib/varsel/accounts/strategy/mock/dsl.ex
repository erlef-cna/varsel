# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Accounts.Strategy.Mock.Dsl do
  @moduledoc false

  alias AshAuthentication.Strategy.Custom
  alias Spark.Dsl.Entity

  @doc false
  @spec dsl :: Custom.entity()
  def dsl do
    %Entity{
      name: :mock,
      describe: """
      A dev-only provider that offers a role to sign in as, in place of an
      external service. See `Varsel.Accounts.Strategy.Mock`.
      """,
      args: [{:optional, :name, :mock}],
      target: Varsel.Accounts.Strategy.Mock,
      schema: [
        name: [
          type: :atom,
          doc: "Uniquely identifies the strategy.",
          default: :mock
        ],
        identity_resource: [
          type: {:or, [{:behaviour, Ash.Resource}, {:in, [false]}]},
          doc: "The resource used to store user identities.",
          default: false
        ],
        register_action_name: [
          type: :atom,
          doc: "The action used to register or sign in a mock user.",
          default: :register_with_mock
        ]
      ]
    }
  end
end
