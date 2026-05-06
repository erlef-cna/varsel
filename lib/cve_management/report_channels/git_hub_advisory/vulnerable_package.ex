# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagement.ReportChannels.GitHubAdvisory.VulnerablePackage do
  @moduledoc """
  Embedded struct representing a vulnerable package in a GitHub security advisory.

  Stored as elements of `GitHubAdvisory.vulnerabilities` (a jsonb array column).
  """

  use Ash.Resource, data_layer: :embedded

  alias CveManagement.ReportChannels.GitHubAdvisory.Package

  attributes do
    attribute :package, Package do
      allow_nil? true
      public? true
    end

    attribute :vulnerable_version_range, :string do
      allow_nil? true
      public? true
    end

    attribute :patched_versions, :string do
      allow_nil? true
      public? true
    end

    attribute :vulnerable_functions, {:array, :string} do
      allow_nil? true
      public? true
    end
  end
end
