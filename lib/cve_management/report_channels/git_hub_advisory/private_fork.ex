# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagement.ReportChannels.GitHubAdvisory.PrivateFork do
  @moduledoc """
  Embedded struct representing the temporary private fork created for a GitHub advisory fix.

  Stored as the `private_fork` column (jsonb map) on `GitHubAdvisory`.
  """

  use Ash.Resource, data_layer: :embedded

  attributes do
    attribute :id, :integer do
      allow_nil? false
      public? true
    end

    attribute :full_name, :string do
      allow_nil? false
      public? true
    end

    attribute :html_url, :string do
      allow_nil? true
      public? true
    end
  end
end
