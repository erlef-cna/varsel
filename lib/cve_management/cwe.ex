# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagement.CWE do
  @moduledoc false
  use Ash.Domain,
    otp_app: :cve_management,
    extensions: [AshAdmin.Domain, AshAi, AshGraphql.Domain]

  alias CveManagement.CWE.Weakness

  admin do
    show? true
  end

  tools do
    tool :list_weaknesses, Weakness, :read do
      load [:related_weakness_relationships]
    end

    tool :get_weakness, Weakness, :get_by_cwe_id do
      load [:related_weakness_relationships]
    end

    tool :search_weaknesses, Weakness, :search do
      load [:related_weakness_relationships]
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
    resource Weakness
    resource CveManagement.CWE.WeaknessRelationship
    resource CveManagement.CWE.CweMetadata
  end
end
