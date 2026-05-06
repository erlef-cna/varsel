# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagement.ReportChannels.GitHubAdvisory.CvssSeverities do
  @moduledoc """
  Embedded struct holding CVSS v3 and v4 scores for a GitHub security advisory.

  Stored as the `cvss_severities` column (jsonb map) on `GitHubAdvisory`.
  """

  use Ash.Resource, data_layer: :embedded

  alias CveManagement.Types.CVSS

  attributes do
    attribute :cvss_v3, CVSS do
      allow_nil? true
      public? true
      constraints version: [:v3]
    end

    attribute :cvss_v4, CVSS do
      allow_nil? true
      public? true
      constraints version: [:v4]
    end
  end
end
