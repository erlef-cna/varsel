# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagement.Accounts.CaseAssignment do
  @moduledoc false
  use Ash.Resource,
    otp_app: :cve_management,
    domain: CveManagement.Accounts,
    data_layer: AshPostgres.DataLayer,
    authorizers: [Ash.Policy.Authorizer]

  postgres do
    table "case_assignments"
    repo CveManagement.Repo
  end

  actions do
    defaults [:read, :destroy, create: []]
  end

  attributes do
    uuid_primary_key :id

    timestamps()
  end

  relationships do
    belongs_to :case, CveManagement.Cases.Case do
      public? true
      allow_nil? false
    end

    belongs_to :user, CveManagement.Accounts.User do
      public? true
      allow_nil? false
    end
  end
end
