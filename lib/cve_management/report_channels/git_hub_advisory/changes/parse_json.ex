# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagement.ReportChannels.GitHubAdvisory.Changes.ParseJson do
  @moduledoc false
  use Ash.Resource.Change

  def change(changeset, _opts, _context) do
    if Ash.Changeset.get_argument(changeset, :raw_data) do
      do_parse(changeset)
    else
      Ash.Changeset.before_action(changeset, fn changeset ->
        do_parse(changeset)
      end)
    end
  end

  defp do_parse(changeset) do
    data = Ash.Changeset.get_argument(changeset, :raw_data)

    changeset
    |> Ash.Changeset.force_change_attribute(:ghsa_id, data["ghsa_id"])
    |> Ash.Changeset.force_change_attribute(:cve_id, data["cve_id"])
    |> Ash.Changeset.force_change_attribute(:summary, data["summary"])
    |> Ash.Changeset.force_change_attribute(:description, data["description"])
    |> Ash.Changeset.force_change_attribute(:severity, data["severity"])
    |> Ash.Changeset.force_change_attribute(:state, data["state"])
    |> Ash.Changeset.force_change_attribute(:url, data["url"])
    |> Ash.Changeset.force_change_attribute(:html_url, data["html_url"])
    |> Ash.Changeset.force_change_attribute(:author, take_github_user(data["author"]))
    |> Ash.Changeset.force_change_attribute(:publisher, take_github_user(data["publisher"]))
    |> Ash.Changeset.force_change_attribute(:github_created_at, data["created_at"])
    |> Ash.Changeset.force_change_attribute(:github_updated_at, data["updated_at"])
    |> Ash.Changeset.force_change_attribute(:github_published_at, data["published_at"])
    |> Ash.Changeset.force_change_attribute(:github_closed_at, data["closed_at"])
    |> Ash.Changeset.force_change_attribute(:github_withdrawn_at, data["withdrawn_at"])
    |> Ash.Changeset.force_change_attribute(:vulnerabilities, data["vulnerabilities"])
    |> Ash.Changeset.force_change_attribute(
      :cvss_severities,
      take_cvss_severities(data["cvss_severities"])
    )
    |> Ash.Changeset.force_change_attribute(:identifiers, data["identifiers"])
    |> Ash.Changeset.force_change_attribute(:credits, data["credits"])
    |> Ash.Changeset.force_change_attribute(
      :credits_detailed,
      Enum.map(data["credits_detailed"] || [], fn c ->
        Map.update(c, "user", nil, &take_github_user/1)
      end)
    )
    |> Ash.Changeset.force_change_attribute(
      :collaborating_users,
      Enum.map(data["collaborating_users"] || [], &take_github_user/1)
    )
    |> Ash.Changeset.force_change_attribute(:collaborating_teams, data["collaborating_teams"])
    |> Ash.Changeset.force_change_attribute(:submission, data["submission"])
    |> Ash.Changeset.force_change_attribute(:private_fork, data["private_fork"])
    |> Ash.Changeset.set_argument(:weakness_ids, parse_cwe_ids(data["cwe_ids"]))
  end

  defp take_cvss_severities(nil), do: nil

  defp take_cvss_severities(m) when is_map(m) do
    %{
      "cvss_v3" => get_in(m, ["cvss_v3", "vector_string"]),
      "cvss_v4" => get_in(m, ["cvss_v4", "vector_string"])
    }
  end

  defp take_github_user(nil), do: nil
  defp take_github_user(u), do: Map.take(u, ["login", "html_url", "avatar_url"])

  defp parse_cwe_ids(nil), do: []

  defp parse_cwe_ids(list) when is_list(list) do
    Enum.flat_map(list, fn id ->
      case Regex.run(~r/^CWE-(\d+)$/, id, capture: :all_but_first) do
        [n] -> [String.to_integer(n)]
        _ -> []
      end
    end)
  end
end
