# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagement.ReportChannels.GitHubAdvisory.Changes.FetchUrl do
  @moduledoc false
  use Ash.Resource.Change

  alias CveManagement.Accounts.GitHubAppToken
  alias CveManagement.GitHub.AdvisoryClient

  def change(changeset, _opts, _context) do
    Ash.Changeset.before_action(changeset, fn changeset ->
      user_id = Ash.Changeset.get_attribute(changeset, :fetched_by_user_id)
      url = Ash.Changeset.get_argument(changeset, :url)

      token =
        Ash.get!(GitHubAppToken, [user_id: user_id],
          authorize?: false,
          domain: CveManagement.Accounts
        )

      loaded_token = Ash.load!(token, [:access_token], authorize?: false)

      {:ok, data} = AdvisoryClient.fetch_advisory(loaded_token.access_token, url)

      Ash.Changeset.force_set_argument(changeset, :raw_data, data)
    end)
  end
end
