# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Derivation do
  @moduledoc """
  Turns the stored vulnerability boundary *facts* of an affected package
  (`Varsel.Cases.VersionEvent` rows: introduced/fixed commit SHAs or explicit
  version boundaries) into the *derived* version data of every distribution
  channel — ready-to-render CVE `versions[]` objects, plus the version ranges
  `cpeApplicability` chains over. A port of the cna repository's
  `gen-affected` pipeline.

  Nothing here is stored as authoritative data: results live in
  `AffectedPackage.derivation_cache` purely for previews, and publishing
  recomputes them.

  ## Resolution rules

  1. Commit SHAs resolve against the package's `repo_url` via
     `Varsel.Cases.Derivation.GitBackend`: the boundary version is the
     earliest release tag containing the commit (per
     `Varsel.Cases.Derivation.Platform` conventions).
  2. Fixed boundaries group into release lines (OTP major / semver minor);
     multiple lines render as `changes[]` chains.
  3. A fixed commit with no containing release tag is a *pending release*:
     it still bounds the `git` channel (the commit exists), but version
     channels exclude the line and report it in `"pending"` — publish blocks
     on it unless the package allows unreleased fixes.
  4. Events scoped to a channel (`package_channel_id` set) replace the
     repo-derived boundaries for that channel entirely and are used verbatim
     (e.g. date boundaries on a `:hosted` channel).
  5. `:otp` channels of packages living in the erlang/otp repository
     translate OTP release tags into per-application versions through
     `Varsel.Cases.Derivation.OtpVersionsTable`; `pkg:otp` channels of other
     repos (Elixir's or rebar3's applications) version with their
     repository's semver tags.

  ## Result shape (JSON-safe, cached in jsonb)

      %{
        "intro" => %{"sha" => _, "tag" => _, "version" => _} | nil,
        "lines" => [%{"key" => [27], "fix_sha" => _, "fix_tag" => _,
                      "fix_version" => _, "pending" => false}],
        "channels" => %{<channel-uuid> => %{"versions" => [...],
                                            "pending" => [...],
                                            "issues" => [...]}},
        "cpe_matches" => [%{"versionStartIncluding" => _,
                            "versionEndExcluding" => _}],
        "issues" => ["..."]
      }
  """

  alias Varsel.Cases.AffectedPackage
  alias Varsel.Cases.Derivation.GitBackend
  alias Varsel.Cases.Derivation.OtpVersionsTable
  alias Varsel.Cases.Derivation.Platform

  @doc """
  Derives version data for an affected package. The package must have
  `:channels` and `:version_events` loaded.
  """
  @spec derive(AffectedPackage.t()) :: {:ok, map()}
  def derive(package) do
    platform = Platform.for_package(package)

    {scoped_events, global_events} =
      Enum.split_with(package.version_events, & &1.package_channel_id)

    {intro, intro_issues} = resolve_intro(package, platform, global_events)
    {lines, line_issues} = resolve_lines(package, platform, global_events)

    channels =
      Map.new(package.channels, fn channel ->
        events = Enum.filter(scoped_events, &(&1.package_channel_id == channel.id))
        {channel.id, derive_channel(channel, platform, intro, lines, events)}
      end)

    # The git/forge entry is implicit: every package with a repository gets
    # one, derived from the same boundary facts.
    git = if package.repo_url, do: derive_git_channel(platform, intro, lines)

    {:ok,
     %{
       "intro" => intro,
       "lines" => lines,
       "channels" => channels,
       "git" => git,
       "cpe_matches" => cpe_matches(platform, intro, lines),
       "issues" => intro_issues ++ line_issues
     }}
  end

  ## ------------------------------------------------------------------ intro

  defp resolve_intro(package, platform, events) do
    case Enum.filter(events, &(&1.event == :introduced)) do
      [] ->
        {nil, ["no introduced boundary fact recorded"]}

      intros ->
        resolved = Enum.map(intros, &resolve_boundary(package, platform, &1))

        issues =
          Enum.flat_map(resolved, fn
            {:issue, message} ->
              [message]

            %{"version" => nil, "sha" => sha} ->
              ["introduced commit #{sha} is not contained in any release tag"]

            _resolved ->
              []
          end)

        case Enum.filter(resolved, &(is_map(&1) and &1["version"] != nil)) do
          [] ->
            {nil, issues}

          resolved_intros ->
            # Multiple introduced facts: the earliest boundary wins.
            intro = Enum.min_by(resolved_intros, &Platform.parse_version(&1["version"]))
            {intro, issues}
        end
    end
  end

  ## ------------------------------------------------------------------ fixes

  defp resolve_lines(package, platform, events) do
    resolved =
      events
      |> Enum.filter(&(&1.event == :fixed))
      |> Enum.map(&resolve_boundary(package, platform, &1))

    issues = Enum.flat_map(resolved, &List.wrap(issue_of(&1)))

    lines =
      resolved
      |> Enum.filter(&is_map/1)
      |> Enum.group_by(fn boundary ->
        case boundary["version"] do
          nil -> :pending
          version -> Platform.group_key(platform, version)
        end
      end)
      |> Enum.flat_map(fn
        {:pending, boundaries} ->
          Enum.map(boundaries, fn boundary ->
            %{
              "key" => nil,
              "fix_sha" => boundary["sha"],
              "fix_tag" => nil,
              "fix_version" => nil,
              "pending" => true
            }
          end)

        {key, boundaries} ->
          boundary = Enum.min_by(boundaries, &Platform.parse_version(&1["version"]))

          [
            %{
              "key" => serialize_key(key),
              "fix_sha" => boundary["sha"],
              "fix_tag" => boundary["tag"],
              "fix_version" => boundary["version"],
              "pending" => false
            }
          ]
      end)
      |> Enum.sort_by(&line_sort/1)

    {lines, issues}
  end

  # Resolves one boundary event to %{"sha", "tag", "version"} (version nil =
  # pending release), or {:issue, message}.
  defp resolve_boundary(_package, _platform, %{version: version} = event) when not is_nil(version) do
    %{"sha" => event.commit_sha, "tag" => nil, "version" => version}
  end

  defp resolve_boundary(%{repo_url: nil}, _platform, event) do
    {:issue, "event #{event.id} has a commit SHA but the package has no repo_url"}
  end

  defp resolve_boundary(package, platform, event) do
    case GitBackend.tags_containing(package.repo_url, event.commit_sha) do
      {:ok, tags} ->
        case Platform.earliest_tag(platform, tags) do
          nil ->
            # The commit exists but no release contains it yet.
            %{"sha" => event.commit_sha, "tag" => nil, "version" => nil}

          tag ->
            %{
              "sha" => event.commit_sha,
              "tag" => tag,
              "version" => Platform.strip_prefix(platform, tag)
            }
        end

      {:error, reason} ->
        {:issue, "cannot resolve commit #{event.commit_sha}: #{inspect(reason)}"}
    end
  end

  defp issue_of({:issue, message}), do: message
  defp issue_of(_resolved), do: nil

  defp serialize_key(nil), do: nil
  defp serialize_key(key) when is_integer(key), do: [key]
  defp serialize_key({major, minor}), do: [major, minor]

  defp deserialize_key(nil), do: nil
  defp deserialize_key([major]), do: major
  defp deserialize_key([major, minor]), do: {major, minor}

  # Newest release line first (gen-affected renders changes[] newest-first).
  defp line_sort(%{"pending" => true}), do: {1, 0}
  defp line_sort(%{"key" => key}), do: {0, Platform.sort_desc(deserialize_key(key))}

  ## --------------------------------------------------------------- channels

  defp derive_channel(channel, platform, intro, lines, scoped_events) do
    cond do
      scoped_events != [] ->
        derive_scoped_channel(channel, platform, scoped_events)

      channel.purl_type == :hosted ->
        %{
          "versions" => [],
          "pending" => [],
          "issues" => ["hosted channels need channel-scoped version events"]
        }

      intro == nil ->
        %{"versions" => [], "pending" => pending_shas(lines), "issues" => []}

      true ->
        derive_repo_channel(channel, platform, intro, lines)
    end
  end

  # Channel-scoped explicit events: used verbatim as one range.
  defp derive_scoped_channel(channel, platform, events) do
    intro = Enum.find(events, &(&1.event == :introduced))
    fixes = Enum.filter(events, &(&1.event == :fixed))
    version_type = version_type(channel, platform)

    cond do
      intro == nil ->
        %{
          "versions" => [],
          "pending" => [],
          "issues" => ["channel-scoped events lack an introduced boundary"]
        }

      fixes == [] ->
        %{
          "versions" => [open_range(boundary_value(intro), version_type)],
          "pending" => [],
          "issues" => []
        }

      true ->
        %{
          "versions" => [
            ranged(boundary_value(intro), Enum.map(fixes, &boundary_value/1), version_type)
          ],
          "pending" => [],
          "issues" => []
        }
    end
  end

  defp boundary_value(%{version: version}) when not is_nil(version), do: version
  defp boundary_value(%{commit_sha: sha}), do: sha

  defp version_type(%{purl_type: :otp}, %{kind: :otp}), do: "otp"
  defp version_type(%{purl_type: :oci}, _platform), do: "other"
  defp version_type(%{purl_type: :hosted}, _platform), do: "date"
  defp version_type(_channel, _platform), do: "semver"

  # Repo-derived channels: registry versions, OTP app versions, OCI tags.
  defp derive_repo_channel(channel, platform, intro, lines) do
    released = Enum.reject(lines, & &1["pending"])
    pending = pending_shas(lines)

    case channel.purl_type do
      :otp when platform.kind == :otp ->
        derive_otp_channel(channel, intro, released, pending)

      :oci ->
        suffixes = if channel.tag_suffixes == [], do: [nil], else: channel.tag_suffixes

        versions =
          Enum.flat_map(suffixes, &release_range(intro, released, "other", oci_tagger(&1)))

        %{"versions" => versions, "pending" => pending, "issues" => []}

      _semver_like ->
        %{
          "versions" => release_range(intro, released, "semver"),
          "pending" => pending,
          "issues" => []
        }
    end
  end

  # The implicit git/forge entry, derived for every package with a repo_url.
  defp derive_git_channel(_platform, nil, _lines) do
    %{"versions" => [], "pending" => [], "issues" => []}
  end

  defp derive_git_channel(platform, intro, lines) do
    released = Enum.reject(lines, & &1["pending"])
    pending = pending_shas(lines)

    # An explicit introduced version ("0" = since the beginning) stands in
    # when no introducing commit is known (see CVE-2025-4754's git entry).
    {git_range, git_issues} =
      case intro["sha"] || intro["version"] do
        nil ->
          {[], ["the introduced boundary has neither a commit SHA nor a version"]}

        intro_boundary ->
          # Every fixed SHA bounds the git range, released or not.
          fix_shas = lines |> Enum.map(& &1["fix_sha"]) |> Enum.reject(&is_nil/1)
          {[ranged_or_open(intro_boundary, fix_shas, "git")], []}
      end

    # OTP packages publish the release-version block ahead of the git
    # block in the same entry (see CVE-2025-4748).
    versions =
      if platform.kind == :otp do
        release_range(intro, released, "otp") ++ git_range
      else
        git_range
      end

    %{"versions" => versions, "pending" => pending, "issues" => git_issues}
  end

  defp derive_otp_channel(channel, intro, released, pending) do
    app = channel.name

    with {:intro, {:ok, intro_version}} <-
           {:intro, OtpVersionsTable.first_shipped_version(intro["tag"] || intro["version"], app)},
         {:fixes, {:ok, fix_versions}} <- {:fixes, otp_fix_versions(released, app)} do
      versions =
        case fix_versions do
          [] -> [open_range(intro_version, "otp")]
          fixes -> [ranged(intro_version, fixes, "otp")]
        end

      %{"versions" => versions, "pending" => pending, "issues" => []}
    else
      {:intro, :error} ->
        %{
          "versions" => [],
          "pending" => pending,
          "issues" => ["cannot resolve #{app}'s introducing version"]
        }

      {:fixes, {:error, release}} ->
        %{
          "versions" => [],
          "pending" => pending,
          "issues" => ["cannot resolve #{app}'s version in #{release}"]
        }
    end
  end

  defp otp_fix_versions(released, app) do
    Enum.reduce_while(released, {:ok, []}, fn line, {:ok, acc} ->
      release = line["fix_tag"] || line["fix_version"]

      case OtpVersionsTable.app_version(release, app) do
        {:ok, version} -> {:cont, {:ok, acc ++ [version]}}
        :error -> {:halt, {:error, release}}
      end
    end)
  end

  # The version block of release-versioned channels: single fix renders as a
  # bounded range, several as a changes[] chain, none as an open range.
  defp release_range(intro, released, version_type, mapper \\ &Function.identity/1) do
    intro_version = mapper.(intro["version"])

    case Enum.map(released, &mapper.(&1["fix_version"])) do
      [] -> [open_range(intro_version, version_type)]
      fixes -> [ranged(intro_version, fixes, version_type)]
    end
  end

  defp ranged(intro, [fix], version_type) do
    %{
      "version" => intro,
      "lessThan" => fix,
      "status" => "affected",
      "versionType" => version_type
    }
  end

  defp ranged(intro, fixes, version_type) do
    %{
      "version" => intro,
      "lessThan" => "*",
      "status" => "affected",
      "versionType" => version_type,
      "changes" => Enum.map(fixes, &%{"at" => &1, "status" => "unaffected"})
    }
  end

  defp ranged_or_open(intro, [], version_type), do: open_range(intro, version_type)
  defp ranged_or_open(intro, fixes, version_type), do: ranged(intro, fixes, version_type)

  defp open_range(intro, version_type) do
    %{
      "version" => intro,
      "lessThan" => "*",
      "status" => "affected",
      "versionType" => version_type
    }
  end

  defp oci_tagger(suffix), do: &oci_tag(&1, suffix)

  defp oci_tag(version, nil), do: "v#{version}"
  defp oci_tag(version, suffix), do: "v#{version}-#{suffix}"

  defp pending_shas(lines) do
    lines |> Enum.filter(& &1["pending"]) |> Enum.map(& &1["fix_sha"]) |> Enum.reject(&is_nil/1)
  end

  ## ---------------------------------------------------------- cpe chaining

  # Chain cpeMatch ranges so they cover intro -> highest fix without overlap:
  # oldest fix line bounds [intro, fix1), the next [line2-start, fix2), ...
  # A legacy intro (pre-semver OTP_R era) or "0" (affected since the
  # beginning) drops the lower bound entirely.
  defp cpe_matches(_platform, nil, _lines), do: []

  defp cpe_matches(platform, intro, lines) do
    released =
      lines |> Enum.reject(& &1["pending"]) |> Enum.sort_by(&line_sort/1) |> Enum.reverse()

    legacy_intro? =
      intro["version"] == "0" or Platform.legacy_version?(platform, intro["version"])

    case released do
      [] ->
        lower = if legacy_intro?, do: nil, else: intro["version"]
        [%{"versionStartIncluding" => lower, "versionEndExcluding" => nil}]

      _lines ->
        {matches, _prev} =
          Enum.map_reduce(released, nil, fn line, prev ->
            lower = cpe_lower_bound(platform, intro, prev, legacy_intro?)

            {%{"versionStartIncluding" => lower, "versionEndExcluding" => line["fix_version"]}, line}
          end)

        matches
    end
  end

  defp cpe_lower_bound(_platform, _intro, nil, true), do: nil
  defp cpe_lower_bound(_platform, intro, nil, false), do: intro["version"]

  defp cpe_lower_bound(platform, _intro, prev, _legacy_intro?) do
    Platform.group_label(platform, Platform.next_key(platform, deserialize_key(prev["key"])))
  end
end
