# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagement.ReportChannels.GitHubAdvisory.GitHubUser do
  @moduledoc """
  Embedded struct representing a GitHub user reference stored within a GitHubAdvisory.

  Used for author, publisher, and collaborating_users fields.
  """

  use Ash.Resource, data_layer: :embedded

  attributes do
    attribute :login, :string do
      allow_nil? false
      public? true
    end

    attribute :html_url, :string do
      allow_nil? true
      public? true
    end

    attribute :avatar_url, :string do
      allow_nil? true
      public? true
    end
  end
end
