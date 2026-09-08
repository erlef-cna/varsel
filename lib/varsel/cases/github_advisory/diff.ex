# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.GitHubAdvisory.Diff do
  @moduledoc """
  Compares a case with the GitHub advisory it is linked to, field by field,
  so a reviewer sees what each side says and where they differ.

  The title and the description compare after whitespace normalization. The
  description is `Varsel.Cases.GitHubAdvisory.Export.description/1` against
  the advisory's. The CVE ID and the CVSS vector compare as they are. CWEs
  compare as a set. Credits compare per person
  (`Varsel.Cases.GitHubAdvisory.People`), by GitHub login where the credit
  carries one. GitHub gives a person one role, so the advisory's role only
  has to be among the person's roles here.

  Affected packages compare per distribution channel: the ranges the case
  **derived** for the channel, in GitHub's spelling from the derivation
  cache, against the ranges the advisory states. The advisory's `ecosystem`
  picks the channel. An `erlang` entry matches the `pkg:hex` channel of that
  name. An `otp` entry matches the `pkg:otp` channel of that name. Any other
  entry matches a channel or a product that carries the name.

  The case needs `Varsel.Cases.GitHubAdvisory.Export.load/0` loaded.
  """

  alias Varsel.Cases.AffectedPackage.Preset
  alias Varsel.Cases.Case
  alias Varsel.Cases.GitHubAdvisory
  alias Varsel.Cases.GitHubAdvisory.Export
  alias Varsel.Cases.GitHubAdvisory.Import
  alias Varsel.Cases.GitHubAdvisory.People

  @typedoc """
  How the two sides relate: `:same`, `:differs`, one side alone, or
  `:not_derived` for a channel the case has but derived no ranges for.
  """
  @type status :: :same | :differs | :ours_only | :theirs_only | :not_derived

  @typedoc """
  One field compared. `ours` and `theirs` hold each side's value in display
  form: a string for prose and the vector, lists for CWEs and credits, and
  `%{ranges: [...], patched: [...]}` for an affected package, whose row also
  names the `package`.
  """
  @type row :: %{
          required(:field) => :title | :description | :cve_id | :cvss_v4 | :weaknesses | :credits | :affected,
          required(:ours) => term(),
          required(:theirs) => term(),
          required(:status) => status(),
          optional(:package) => String.t()
        }

  @doc "Every compared field of the case against the advisory, affected packages last."
  @spec rows(Case.t(), GitHubAdvisory.t()) :: [row()]
  def rows(case_record, advisory) do
    params = Import.case_params(advisory)
    children = Import.child_params(advisory)

    [
      prose(:title, case_record.title, params[:title]),
      prose(:description, Export.description(case_record), params[:description_md]),
      scalar(:cve_id, case_record.cve_id, Import.blank_to_nil(advisory["cve_id"])),
      scalar(:cvss_v4, Export.vector(case_record.cvss_v4), params[:cvss_v4]),
      set(
        :weaknesses,
        Enum.map(case_record.weaknesses, & &1.cwe_id),
        Enum.map(children.weaknesses, & &1.cwe_id)
      ),
      credits(People.people(case_record.credits), People.people(children.credits))
    ] ++ affected_rows(case_record, Import.vulnerabilities(advisory))
  end

  @doc """
  Whether the advisory can add to a row: a value the case lacks or has
  differently, a person or role it lacks, a package it has no channel for.

  Three rows are never pulled. Derived ranges come from the case's own
  boundaries. The description is rendered from the case's own sections, and
  one document cannot be split back into them. A CVE ID is assigned from the
  pool here, never taken from GitHub.
  """
  @spec pullable?(row()) :: boolean()
  def pullable?(%{field: :affected, status: status}), do: status == :theirs_only
  def pullable?(%{field: field}) when field in [:description, :cve_id], do: false
  def pullable?(%{status: status}) when status in [:same, :ours_only, :not_derived], do: false

  def pullable?(%{field: :credits, ours: ours, theirs: theirs}) do
    Enum.any?(theirs, fn person ->
      case Enum.find(ours, &(&1.login == person.login)) do
        nil -> true
        here -> not Enum.all?(person.roles, &(&1 in here.roles))
      end
    end)
  end

  def pullable?(%{field: :weaknesses, ours: ours, theirs: theirs}),
    do: not MapSet.subset?(MapSet.new(theirs), MapSet.new(ours))

  def pullable?(%{theirs: theirs}), do: not is_nil(theirs)

  @doc """
  Whether the case can write a row to the advisory: a value the advisory
  lacks or has differently, a person with a GitHub account it lacks, derived
  ranges that differ from its own. Pushing affected packages replaces the
  advisory's list with the case's derived ranges, so a channel that derived
  nothing offers none.
  """
  @spec pushable?(row()) :: boolean()
  def pushable?(%{status: status}) when status in [:same, :theirs_only, :not_derived], do: false

  def pushable?(%{field: :credits, ours: ours, theirs: theirs}) do
    theirs_logins = MapSet.new(theirs || [], & &1.login)

    Enum.any?(ours, &(is_binary(&1.login) and not MapSet.member?(theirs_logins, &1.login)))
  end

  def pushable?(%{field: :weaknesses, ours: ours, theirs: theirs}),
    do: not MapSet.subset?(MapSet.new(ours), MapSet.new(theirs || []))

  def pushable?(%{ours: ours}), do: not is_nil(ours)

  ## ------------------------------------------------------------- scalars

  defp prose(field, ours, theirs) do
    row(field, ours, theirs, normalize_prose(ours) == normalize_prose(theirs))
  end

  defp scalar(field, ours, theirs), do: row(field, ours, theirs, ours == theirs)

  defp row(field, nil, nil, _same?), do: %{field: field, ours: nil, theirs: nil, status: :same}

  defp row(field, ours, nil, _same?), do: %{field: field, ours: ours, theirs: nil, status: :ours_only}

  defp row(field, nil, theirs, _same?), do: %{field: field, ours: nil, theirs: theirs, status: :theirs_only}

  defp row(field, ours, theirs, same?) do
    %{field: field, ours: ours, theirs: theirs, status: if(same?, do: :same, else: :differs)}
  end

  defp normalize_prose(nil), do: nil

  defp normalize_prose(text) when is_binary(text) do
    text |> String.replace("\r\n", "\n") |> String.split(~r/\s+/, trim: true) |> Enum.join(" ")
  end

  ## ---------------------------------------------------------------- sets

  defp set(field, ours, theirs) do
    ours = Enum.uniq(ours)
    theirs = Enum.uniq(theirs)

    status =
      cond do
        ours == [] and theirs == [] -> :same
        ours == [] -> :theirs_only
        theirs == [] -> :ours_only
        MapSet.equal?(MapSet.new(ours), MapSet.new(theirs)) -> :same
        true -> :differs
      end

    %{field: field, ours: ours, theirs: theirs, status: status}
  end

  defp credits(ours, theirs) do
    on_github = Enum.filter(ours, &is_binary(&1.login))

    status =
      cond do
        on_github == [] and theirs == [] -> :same
        on_github == [] -> :theirs_only
        theirs == [] -> :ours_only
        same_people?(on_github, theirs) -> :same
        true -> :differs
      end

    %{field: :credits, ours: ours, theirs: theirs, status: status}
  end

  defp same_people?(ours, theirs) do
    MapSet.equal?(MapSet.new(ours, & &1.login), MapSet.new(theirs, & &1.login)) and
      Enum.all?(theirs, fn person ->
        here = Enum.find(ours, &(&1.login == person.login))
        Enum.all?(person.roles, &(&1 in here.roles))
      end)
  end

  ## ------------------------------------------------------------ affected

  @doc """
  Whether the case already carries one of the advisory's affected packages
  (an `Import.affected_package/0`): a preset by its product, a plain package
  by any of its entries matching a channel the way the diff matches them.
  """
  @spec package_present?(Case.t(), Import.affected_package()) :: boolean()
  def package_present?(case_record, %{preset: preset}) when not is_nil(preset) do
    product = Preset.attributes(preset).product

    Enum.any?(case_record.affected_packages, &same_name?(&1.product, product))
  end

  def package_present?(case_record, %{vulnerabilities: vulnerabilities}) do
    channels = channels(case_record)

    Enum.any?(vulnerabilities, fn vulnerability ->
      Enum.any?(channels, &matches?(&1, vulnerability))
    end)
  end

  defp affected_rows(case_record, vulnerabilities) do
    channels = channels(case_record)

    matches =
      Enum.map(vulnerabilities, fn vulnerability ->
        {vulnerability, Enum.find(channels, &matches?(&1, vulnerability))}
      end)

    matched = for {_vulnerability, %{id: id}} <- matches, do: id

    theirs_rows =
      for {vulnerability, channel} <- matches do
        affected_row(
          package_label(vulnerability),
          channel && channel.github_ranges,
          vulnerability
        )
      end

    ours_only =
      for channel <- channels, channel.id not in matched, channel.github_ranges != [] do
        affected_row(channel.label, channel.github_ranges, nil)
      end

    theirs_rows ++ ours_only
  end

  defp channels(case_record) do
    for package <- case_record.affected_packages, channel <- package.channels do
      cached =
        get_in(package.derivation_cache || %{}, ["channels", channel.id, "github_ranges"]) || []

      %{
        id: channel.id,
        purl_type: channel.purl_type,
        name: channel.name,
        product: package.product,
        label: channel_label(channel),
        github_ranges: cached
      }
    end
  end

  defp affected_row(package, nil, vulnerability) do
    %{
      field: :affected,
      package: package,
      ours: nil,
      theirs: theirs_ranges(vulnerability),
      status: :theirs_only
    }
  end

  defp affected_row(package, github_ranges, nil) do
    %{
      field: :affected,
      package: package,
      ours: ours_ranges(github_ranges),
      theirs: nil,
      status: :ours_only
    }
  end

  defp affected_row(package, github_ranges, vulnerability) do
    ours = ours_ranges(github_ranges)
    theirs = theirs_ranges(vulnerability)

    status =
      cond do
        ours.ranges == [] ->
          :not_derived

        MapSet.new(ours.ranges) == MapSet.new(theirs.ranges) and
            MapSet.new(ours.patched) == MapSet.new(theirs.patched) ->
          :same

        true ->
          :differs
      end

    %{field: :affected, package: package, ours: ours, theirs: theirs, status: status}
  end

  defp ours_ranges(github_ranges) do
    %{
      ranges: Enum.map(github_ranges, & &1["vulnerable_version_range"]),
      patched: github_ranges |> Enum.flat_map(&(&1["patched_versions"] || [])) |> Enum.uniq()
    }
  end

  defp theirs_ranges(%{vulnerable_version_range: range, patched_versions: patched}) do
    %{ranges: List.wrap(range), patched: patched}
  end

  defp matches?(%{purl_type: "hex", name: name}, %{ecosystem: "erlang", name: theirs}), do: same_name?(name, theirs)

  defp matches?(_channel, %{ecosystem: "erlang"}), do: false

  defp matches?(%{purl_type: "otp", name: name}, %{ecosystem: "otp", name: theirs}), do: same_name?(name, theirs)

  defp matches?(_channel, %{ecosystem: "otp"}), do: false

  defp matches?(%{name: name, product: product}, %{name: theirs}) do
    same_name?(name, theirs) or same_name?(product, theirs)
  end

  defp same_name?(name, theirs) when is_binary(name) and is_binary(theirs) do
    String.downcase(name) == String.downcase(theirs)
  end

  defp same_name?(_name, _theirs), do: false

  defp package_label(%{ecosystem: nil, name: name}), do: name
  defp package_label(%{ecosystem: ecosystem, name: name}), do: "#{ecosystem}/#{name}"

  defp channel_label(%{kind: :service, domain: domain}), do: domain || "service"

  defp channel_label(%{purl_type: purl_type, name: name}) when is_binary(name), do: "#{purl_type}/#{name}"

  defp channel_label(%{purl_type: purl_type}), do: to_string(purl_type)
end
