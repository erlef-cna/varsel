# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagement.ReportChannels.GitHubAdvisory.Submission do
  @moduledoc """
  Embedded struct representing private vulnerability report submission metadata.

  Stored as the `submission` column (jsonb map) on `GitHubAdvisory`.
  """

  use Ash.Resource, data_layer: :embedded

  attributes do
    attribute :accepted, :boolean do
      allow_nil? false
      public? true
    end
  end
end
