# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagement.ReportChannels.GitHubAdvisory.Package do
  @moduledoc """
  Embedded struct representing a package affected by a GitHub security advisory vulnerability.
  """

  use Ash.Resource, data_layer: :embedded

  attributes do
    # GitHub can return packages without an ecosystem (e.g. draft advisories
    # where the reporter has not selected one yet)
    attribute :ecosystem, :string do
      allow_nil? true
      public? true
    end

    attribute :name, :string do
      allow_nil? true
      public? true
    end
  end
end
