# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagement.ReportChannels.GitHubAdvisory.CreditDetailed do
  @moduledoc """
  Embedded struct representing a detailed credit entry from the GitHub API (read-only).

  Includes the user object and the acceptance state.
  Stored as elements of `GitHubAdvisory.credits_detailed` (a jsonb array column).
  """

  use Ash.Resource, data_layer: :embedded

  alias CveManagement.ReportChannels.GitHubAdvisory.GitHubUser

  attributes do
    attribute :user, GitHubUser do
      allow_nil? false
      public? true
    end

    attribute :type, CveManagement.ReportChannels.GitHubAdvisory.CreditType do
      allow_nil? false
      public? true
    end

    attribute :state, CveManagement.ReportChannels.GitHubAdvisory.CreditState do
      allow_nil? false
      public? true
    end
  end
end
