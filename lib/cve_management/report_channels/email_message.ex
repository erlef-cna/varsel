# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagement.ReportChannels.EmailMessage do
  @moduledoc false
  use Ash.Resource,
    otp_app: :cve_management,
    domain: CveManagement.ReportChannels,
    authorizers: [Ash.Policy.Authorizer],
    data_layer: AshPostgres.DataLayer

  postgres do
    table "email_messages"
    repo CveManagement.Repo
  end

  actions do
    defaults [
      :read,
      create: [
        :message_id,
        :in_reply_to,
        :from_email,
        :from_name,
        :subject,
        :body_text,
        :body_html,
        :gpg_status,
        :raw_headers,
        :processed_at
      ]
    ]
  end

  attributes do
    uuid_primary_key :id

    attribute :message_id, :string do
      allow_nil? false
      public? true
    end

    attribute :in_reply_to, :string do
      public? true
    end

    attribute :from_email, :string do
      allow_nil? false
      public? true
    end

    attribute :from_name, :string do
      public? true
    end

    attribute :subject, :string do
      allow_nil? false
      public? true
    end

    attribute :body_text, :string do
      allow_nil? false
      public? true
    end

    attribute :body_html, :string do
      public? true
    end

    attribute :gpg_status, :atom do
      allow_nil? false
      public? true
    end

    attribute :raw_headers, :map do
      allow_nil? false
      public? true
    end

    attribute :processed_at, :utc_datetime do
      public? true
    end

    timestamps()
  end

  relationships do
    belongs_to :case, CveManagement.Cases.Case do
      public? true
      allow_nil? true
    end
  end
end
