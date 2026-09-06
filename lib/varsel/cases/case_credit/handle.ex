# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.CaseCredit.Handle do
  @moduledoc """
  A provider account a credited person goes by, stored as the provider spells
  it. It is what links a credit to the account that signs in with it.
  """

  use Ash.Resource,
    data_layer: :embedded,
    extensions: [AshGraphql.Resource]

  alias Varsel.Cases.CaseInvite.Strategy

  graphql do
    type :case_credit_handle
  end

  attributes do
    attribute :strategy, Strategy do
      description "The provider the handle names the person at."
      allow_nil? false
      public? true
    end

    attribute :username, :ci_string do
      description "The handle at that provider."
      allow_nil? false
      public? true
    end
  end
end
