# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagement.ReportChannels.GitHubAdvisory.Identifier do
  @moduledoc """
  Embedded struct representing an advisory identifier (CVE or GHSA).

  Stored as elements of `GitHubAdvisory.identifiers` (a jsonb array column).
  """

  use Ash.Resource, data_layer: :embedded

  attributes do
    attribute :type, CveManagement.ReportChannels.GitHubAdvisory.IdentifierType do
      allow_nil? false
      public? true
    end

    attribute :value, :string do
      allow_nil? false
      public? true
    end
  end
end
