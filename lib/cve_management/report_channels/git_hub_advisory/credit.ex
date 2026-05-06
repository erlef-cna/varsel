# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagement.ReportChannels.GitHubAdvisory.Credit do
  @moduledoc """
  Embedded struct representing a credit entry in a GitHub security advisory.

  Stored as elements of `GitHubAdvisory.credits` (a jsonb array column).
  This is the writable form — only login and type.
  """

  use Ash.Resource, data_layer: :embedded

  attributes do
    attribute :login, :string do
      allow_nil? false
      public? true
    end

    attribute :type, CveManagement.ReportChannels.GitHubAdvisory.CreditType do
      allow_nil? false
      public? true
    end
  end
end
