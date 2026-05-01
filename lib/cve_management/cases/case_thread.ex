# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagement.Cases.CaseThread do
  @moduledoc false
  use Ash.Resource,
    otp_app: :cve_management,
    domain: CveManagement.Cases,
    authorizers: [Ash.Policy.Authorizer],
    data_layer: AshPostgres.DataLayer

  postgres do
    table "case_threads"
    repo CveManagement.Repo
  end

  actions do
    defaults [
      :read,
      create: [
        :channel,
        :direction,
        :body_raw,
        :body_html,
        :sender_email,
        :sender_name,
        :message_id,
        :in_reply_to,
        :gpg_signed,
        :gpg_encrypted
      ]
    ]
  end

  attributes do
    uuid_primary_key :id

    attribute :channel, :atom do
      allow_nil? false
      public? true
    end

    attribute :direction, :atom do
      allow_nil? false
      public? true
    end

    attribute :body_raw, :string do
      allow_nil? false
      public? true
    end

    attribute :body_html, :string do
      public? true
    end

    attribute :sender_email, :string do
      public? true
    end

    attribute :sender_name, :string do
      public? true
    end

    attribute :message_id, :string do
      public? true
    end

    attribute :in_reply_to, :string do
      public? true
    end

    attribute :gpg_signed, :boolean do
      public? true
    end

    attribute :gpg_encrypted, :boolean do
      public? true
    end

    timestamps()
  end

  relationships do
    belongs_to :case, CveManagement.Cases.Case do
      public? true
      allow_nil? false
    end
  end
end
