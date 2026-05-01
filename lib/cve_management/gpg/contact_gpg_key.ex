# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagement.GPG.ContactGpgKey do
  @moduledoc false
  use Ash.Resource,
    otp_app: :cve_management,
    domain: CveManagement.GPG,
    authorizers: [Ash.Policy.Authorizer],
    data_layer: AshPostgres.DataLayer

  postgres do
    table "contact_gpg_keys"
    repo CveManagement.Repo
  end

  actions do
    defaults [:read, create: [:email, :armored_key, :fingerprint]]
  end

  attributes do
    uuid_primary_key :id

    attribute :email, :string do
      allow_nil? false
      public? true
    end

    attribute :armored_key, :string do
      allow_nil? false
      public? true
    end

    attribute :fingerprint, :string do
      allow_nil? false
      public? true
    end

    timestamps()
  end
end
