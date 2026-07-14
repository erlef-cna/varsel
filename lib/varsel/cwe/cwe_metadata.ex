# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CWE.CweMetadata do
  @moduledoc """
  Singleton resource that stores sync metadata for the CWE catalog feed.

  The table always contains at most one row, keyed by the constant string
  primary key `"singleton"`. The `last_modified` field holds the HTTP
  `Last-Modified` header value from the last successful CWE download, used
  as the `If-Modified-Since` value on subsequent requests to avoid unnecessary
  re-downloads.
  """

  use Ash.Resource,
    otp_app: :varsel,
    domain: Varsel.CWE,
    authorizers: [Ash.Policy.Authorizer],
    data_layer: AshPostgres.DataLayer

  postgres do
    table "cwe_metadata"
    repo Varsel.Repo
  end

  actions do
    read :read do
      primary? true
    end

    create :upsert do
      accept [:last_modified, :last_synced_at]
      upsert? true
      upsert_fields [:last_modified, :last_synced_at]
    end
  end

  policies do
    bypass AshOban.Checks.AshObanInteraction do
      authorize_if always()
    end

    policy action_type(:read) do
      authorize_if always()
    end
  end

  attributes do
    attribute :singleton_key, :string do
      primary_key? true
      allow_nil? false
      default "singleton"
      writable? false
      public? false
    end

    attribute :last_modified, :string do
      allow_nil? true
      public? true
      description "HTTP Last-Modified header value from the last successful CWE catalog download."
    end

    attribute :last_synced_at, :utc_datetime do
      allow_nil? true
      public? true
    end
  end
end
