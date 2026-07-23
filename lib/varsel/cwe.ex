# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CWE do
  @moduledoc false
  use Ash.Domain,
    otp_app: :varsel,
    extensions: [AshAdmin.Domain, AshAi, AshGraphql.Domain]

  alias Varsel.CWE.Weakness

  admin do
    show? true
  end

  tools do
    tool :list_weaknesses, Weakness, :read do
      load [:related_weakness_relationships, :related_attack_patterns]
    end

    tool :get_weakness, Weakness, :get_by_cwe_id do
      load [:related_weakness_relationships, :related_attack_patterns]
    end

    tool :search_weaknesses, Weakness, :search do
      load [:related_weakness_relationships, :related_attack_patterns]
    end
  end

  graphql do
    queries do
      list Weakness, :list_weaknesses, :read
      get Weakness, :get_weakness, :get_by_cwe_id, identity: false
      list Weakness, :search_weaknesses, :search
    end
  end

  resources do
    resource Weakness do
      define :list_weaknesses, action: :read
      define :get_weakness, action: :get_by_cwe_id, args: [:cwe_id]
      define :search_weaknesses, action: :search, args: [:query]
      define :upsert_weakness, action: :upsert
      define :sync_cwe_catalog, action: :sync_cwe_catalog
    end

    resource Varsel.CWE.WeaknessRelationship do
      define :list_weakness_relationships, action: :read
      define :create_weakness_relationship, action: :create
      define :update_weakness_relationship, action: :update
      define :destroy_weakness_relationship, action: :destroy
    end

    resource Varsel.CWE.CweMetadata do
      define :read_cwe_metadata, action: :read
      define :upsert_cwe_metadata, action: :upsert
    end
  end
end
