# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagement.ReportChannels.GitHubAdvisory.CollaboratingTeam do
  @moduledoc """
  Embedded struct representing a collaborating team on a GitHub security advisory.

  Stored as elements of `GitHubAdvisory.collaborating_teams` (a jsonb array column).
  """

  use Ash.Resource, data_layer: :embedded

  attributes do
    attribute :id, :integer do
      allow_nil? false
      public? true
    end

    attribute :name, :string do
      allow_nil? false
      public? true
    end

    attribute :slug, :string do
      allow_nil? false
      public? true
    end

    attribute :html_url, :string do
      allow_nil? true
      public? true
    end
  end
end
