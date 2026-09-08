# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.GitHubAdvisory.Import do
  @moduledoc """
  Reads a GitHub security advisory into case params and child rows. It is
  the GitHub counterpart of `Varsel.Cases.Case.Import`.

  ## What transfers

  `summary` becomes the title. `description` becomes the description
  markdown. The CVSS **v4** vector becomes the case vector, since the case is
  v4-only. `published_at` becomes the public date. CWEs come from `cwe_ids`.
  Credits come from `credits_detailed`, or from `credits` on a global entry,
  with their GitHub login and role. Declined credits are dropped.

  ## Affected packages

  The case stores boundary facts and derives version ranges from them. An
  advisory states ranges and nothing about where they come from. So a
  `vulnerabilities[]` entry becomes a package with its distribution channel
  and **no boundaries**. An `erlang` package gets a `pkg:hex` channel. The
  well-known repositories (erlang/otp, elixir-lang/elixir, gleam-lang/gleam)
  go through their presets, with the entries' names as the affected
  applications. Any other entry is a package with no channel, for a person to
  place. The repository owner is the vendor. The ranges travel with the
  package, for `Varsel.Cases.GitHubAdvisory.Diff` to compare with the
  derived ones.

  GitHub's `ecosystem` is free text on a repository advisory. erlang/otp
  writes `otp` for its applications and leaves it empty for the release.
  """

  alias Varsel.Cases.AffectedPackage.Preset
  alias Varsel.Cases.CaseCredit.CreditType
  alias Varsel.Cases.GitHubAdvisory
  alias Varsel.Cases.GitHubAdvisory.Ranges

  @typedoc "A credit as GitHub states it: a login and one role."
  @type credit :: %{
          login: String.t(),
          credit_type: CreditType.t(),
          position: non_neg_integer()
        }

  @typedoc "One `vulnerabilities[]` entry, ranges parsed."
  @type vulnerability :: %{
          ecosystem: String.t() | nil,
          name: String.t(),
          vulnerable_version_range: String.t() | nil,
          patched_versions: [String.t()],
          position: non_neg_integer()
        }

  @typedoc """
  A package to create for the advisory: through a preset with the affected
  applications, or as a plain package with the channels an advisory can name.
  """
  @type affected_package :: %{
          preset: Preset.t() | nil,
          applications: [String.t()],
          attributes: %{
            optional(:vendor) => String.t(),
            optional(:product) => String.t(),
            optional(:repo_url) => String.t()
          },
          channels: [%{purl_type: String.t(), name: String.t()}],
          vulnerabilities: [vulnerability()]
        }

  @presets %{
    "https://github.com/erlang/otp" => :otp,
    "https://github.com/elixir-lang/elixir" => :elixir,
    "https://github.com/gleam-lang/gleam" => :gleam
  }

  @doc """
  Case params read from the advisory, only the keys with a value.
  """
  @spec case_params(GitHubAdvisory.t()) :: map()
  def case_params(advisory) when is_map(advisory) do
    %{}
    |> put_present(:title, blank_to_nil(advisory["summary"]))
    |> put_present(:description_md, prose(advisory["description"]))
    |> put_present(:cvss_v4, cvss_v4(advisory))
    |> put_present(:date_public, GitHubAdvisory.time(advisory["published_at"]))
  end

  @doc """
  The child rows read from the advisory: `weaknesses` as CaseWeakness params,
  `credits` as GitHub states them, and `affected` as packages to create.
  """
  @spec child_params(GitHubAdvisory.t()) :: %{
          weaknesses: [map()],
          credits: [credit()],
          affected: [affected_package()]
        }
  def child_params(advisory) when is_map(advisory) do
    %{weaknesses: weaknesses(advisory), credits: credits(advisory), affected: affected(advisory)}
  end

  @doc "The `vulnerabilities[]` entries, ranges parsed, in advisory order."
  @spec vulnerabilities(GitHubAdvisory.t()) :: [vulnerability()]
  def vulnerabilities(advisory) do
    for {entry, index} <- Enum.with_index(List.wrap(advisory["vulnerabilities"])),
        name = blank_to_nil(get_in(entry, ["package", "name"])) do
      %{
        ecosystem: entry |> get_in(["package", "ecosystem"]) |> ecosystem(),
        name: name,
        vulnerable_version_range: Ranges.normalize(entry["vulnerable_version_range"]),
        patched_versions: Ranges.split_versions(entry["patched_versions"] || entry["first_patched_version"]),
        position: index
      }
    end
  end

  @doc "A string with content, or nil for nil, a blank, or a value that is not a string."
  @spec blank_to_nil(term()) :: String.t() | nil
  def blank_to_nil(value) when is_binary(value) do
    if String.trim(value) == "", do: nil, else: value
  end

  def blank_to_nil(_value), do: nil

  # GitHub's editor saves prose with CRLF line endings. The case, its diff and
  # its rendered record speak LF.
  defp prose(text) do
    case blank_to_nil(text) do
      nil -> nil
      text -> String.replace(text, "\r\n", "\n")
    end
  end

  defp cvss_v4(advisory) do
    advisory |> get_in(["cvss_severities", "cvss_v4", "vector_string"]) |> blank_to_nil()
  end

  defp weaknesses(advisory) do
    ids =
      case advisory["cwe_ids"] do
        [_id | _rest] = ids -> ids
        _absent -> for %{"cwe_id" => id} <- List.wrap(advisory["cwes"]), do: id
      end

    ids
    |> Enum.map(&numeric_id(&1, "CWE"))
    |> Enum.reject(&is_nil/1)
    |> Enum.uniq()
    |> Enum.with_index()
    |> Enum.map(fn {cwe_id, index} -> %{cwe_id: cwe_id, position: index} end)
  end

  # Only `credits_detailed` carries a credit's acceptance state. A global
  # entry carries `credits` alone.
  defp credits(advisory) do
    entries =
      case advisory["credits_detailed"] do
        [_credit | _rest] = detailed -> detailed
        _absent -> List.wrap(advisory["credits"])
      end

    entries
    |> Enum.reject(&(&1["state"] == "declined"))
    |> Enum.flat_map(fn credit ->
      case credit["login"] || get_in(credit, ["user", "login"]) do
        login when is_binary(login) and login != "" ->
          [%{login: login, credit_type: credit_type(credit["type"])}]

        _no_login ->
          []
      end
    end)
    |> Enum.with_index()
    |> Enum.map(fn {credit, index} -> Map.put(credit, :position, index) end)
  end

  defp credit_type(type) when is_binary(type) do
    case CreditType.cast_input(type, []) do
      {:ok, credit_type} -> credit_type
      _unknown -> :other
    end
  end

  defp credit_type(_type), do: :other

  defp affected(advisory) do
    vulnerabilities = vulnerabilities(advisory)
    repository = GitHubAdvisory.repository(advisory)

    case Map.get(@presets, GitHubAdvisory.repo_url(advisory)) do
      nil -> Enum.map(vulnerabilities, &plain_package(&1, repository))
      preset -> [preset_package(preset, vulnerabilities)]
    end
  end

  defp preset_package(preset, vulnerabilities) do
    applications =
      for %{ecosystem: ecosystem, name: name} <- vulnerabilities,
          Preset.applications?(preset) and ecosystem not in [nil, "erlang"],
          uniq: true,
          do: name

    %{
      preset: preset,
      applications: applications,
      attributes: %{},
      channels: [],
      vulnerabilities: vulnerabilities
    }
  end

  defp plain_package(%{ecosystem: "erlang", name: name} = vulnerability, repository) do
    plain = plain_package(%{vulnerability | ecosystem: nil}, repository)

    %{plain | channels: [%{purl_type: "hex", name: name}], vulnerabilities: [vulnerability]}
  end

  defp plain_package(%{name: name} = vulnerability, repository) do
    %{
      preset: nil,
      applications: [],
      attributes: attributes(name, repository),
      channels: [],
      vulnerabilities: [vulnerability]
    }
  end

  defp attributes(name, {owner, repo}) do
    %{vendor: owner, product: name, repo_url: "https://github.com/#{owner}/#{repo}"}
  end

  defp attributes(name, nil), do: %{vendor: name, product: name}

  defp ecosystem(value) when is_binary(value) do
    value |> String.trim() |> String.downcase() |> blank_to_nil()
  end

  defp ecosystem(_value), do: nil

  defp numeric_id(value, prefix) when is_binary(value) do
    case Integer.parse(String.trim_leading(value, prefix <> "-")) do
      {id, ""} -> id
      _not_numeric -> nil
    end
  end

  defp numeric_id(_value, _prefix), do: nil

  defp put_present(params, _key, nil), do: params
  defp put_present(params, key, value), do: Map.put(params, key, value)
end
