# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Derivation do
  @moduledoc """
  Turns the stored vulnerability boundary *facts* of an affected package
  (`Varsel.Cases.VersionEvent` rows: introduced/fixed commit SHAs or explicit
  version boundaries) into the *derived* version data of every distribution
  channel — ready-to-render CVE `versions[]` objects, plus the ranges
  `cpeApplicability` covers.

  Nothing here is stored as authoritative data: results live in
  `AffectedPackage.derivation_cache` purely for previews, and publishing
  recomputes them.

  ## Pipeline

  1. Repo-derived channels: the package's introduced/fixed commit SHAs run
     through `Varsel.Cases.Reachability`, which labels every release tag
     affected/safe from git containment and flattens them into
     `[from, until)` ranges. `Varsel.Cases.Derivation.Emit` then shapes those
     neutral ranges into each channel's `versions[]` (registry semver, OTP
     release versions, OTP per-application versions via `OtpVersionsTable`, OCI
     tag flavours) and the implicit git/forge entry, which carries commit SHAs
     alone.
  2. Channel-scoped events (`package_channel_id` set, e.g. date boundaries on a
     `:hosted` channel) replace the repo derivation for that channel and are
     used verbatim.
  3. A fixed commit contained in no release is *pending*: it still bounds the
     git channel, is reported in `"pending"`, and blocks publishing unless the
     package allows unreleased fixes.

  ## Result shape (JSON-safe, cached in jsonb, all string keys)

      %{
        "channels" => %{<channel-uuid> => %{"versions" => [...],
                                            "pending" => [...],
                                            "issues" => [...]}},
        "git" => %{"versions" => [...], "pending" => [...], "issues" => [...]} | nil,
        "cpe_matches" => [%{"versionStartIncluding" => _, "versionEndExcluding" => _}],
        "call_outs" => [%{...}],
        "issues" => ["..."]
      }
  """

  alias Varsel.Cases.AffectedPackage
  alias Varsel.Cases.Derivation.Emit
  alias Varsel.Cases.Derivation.Platform
  alias Varsel.Cases.Reachability

  @doc """
  Derives version data for an affected package. The package must have
  `:channels` and `:version_events` loaded.
  """
  @spec derive(AffectedPackage.t()) :: {:ok, map()}
  def derive(package) do
    platform = Platform.for_package(package)

    {scoped_events, global_events} =
      Enum.split_with(package.version_events, & &1.package_channel_id)

    reach = reachability(package, platform, global_events)
    pending = reach.pending_fixes

    {intro_shas, _fixes} = boundary_shas(global_events)

    emit_opts = [
      otp_platform?: platform.kind == :otp,
      otp_root_intro?: Enum.any?(intro_shas, &Emit.otp_root_commit?/1)
    ]

    channels =
      Map.new(package.channels, fn channel ->
        events = Enum.filter(scoped_events, &(&1.package_channel_id == channel.id))
        {channel.id, derive_channel(channel, platform, reach, events, emit_opts, pending)}
      end)

    git =
      if package.repo_url do
        {intros, fixes} = boundary_shas(global_events)

        intros
        |> Emit.git(fixes, emit_opts)
        |> Map.put("pending", pending)
      end

    {:ok,
     %{
       "channels" => channels,
       "git" => git,
       "cpe_matches" => Emit.cpe_matches(reach.ranges),
       "call_outs" => reach.call_outs,
       "issues" => reach.issues
     }}
  end

  # Run the reachability engine over the package's global commit facts. Without a
  # repo_url (or without commit facts) there is nothing to resolve.
  defp reachability(%{repo_url: nil}, _platform, _events), do: empty_reachability()

  defp reachability(package, platform, events) do
    {intros, fixes} = boundary_shas(events)

    if intros == [] and fixes == [] do
      empty_reachability()
    else
      case Reachability.derive(package.repo_url, intros, fixes,
             comparator: platform.kind,
             include_prereleases: package.include_prereleases
           ) do
        {:ok, result} ->
          result

        {:error, reason} ->
          %{empty_reachability() | issues: ["cannot resolve versions: #{inspect(reason)}"]}
      end
    end
  end

  defp empty_reachability do
    %{ranges: [], call_outs: [], open?: false, pending_fixes: [], issues: []}
  end

  # Introduced / fixed commit SHAs from the global (non-channel-scoped) events.
  defp boundary_shas(events) do
    {intros, fixes} =
      events
      |> Enum.filter(& &1.commit_sha)
      |> Enum.split_with(&(&1.event == :introduced))

    {Enum.map(intros, & &1.commit_sha), Enum.map(fixes, & &1.commit_sha)}
  end

  ## --------------------------------------------------------------- channels

  defp derive_channel(channel, platform, reach, scoped_events, emit_opts, pending) do
    cond do
      scoped_events != [] ->
        derive_scoped_channel(channel, platform, scoped_events)

      channel.purl_type == :hosted ->
        %{
          "versions" => [],
          "pending" => [],
          "issues" => ["hosted channels need channel-scoped version events"]
        }

      true ->
        channel
        |> Emit.channel(reach.ranges, emit_opts)
        |> Map.put("pending", pending)
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
        versions =
          for fix <- fixes,
              do: bounded_range(boundary_value(intro), boundary_value(fix), version_type)

        %{"versions" => versions, "pending" => [], "issues" => []}
    end
  end

  defp boundary_value(%{version: version}) when not is_nil(version), do: version
  defp boundary_value(%{commit_sha: sha}), do: sha

  defp version_type(%{purl_type: :otp}, %{kind: :otp}), do: "otp"
  defp version_type(%{purl_type: :oci}, _platform), do: "other"
  defp version_type(%{purl_type: :hosted}, _platform), do: "date"
  defp version_type(_channel, _platform), do: "semver"

  defp bounded_range(from, until, version_type) do
    %{
      "version" => from,
      "lessThan" => until,
      "status" => "affected",
      "versionType" => version_type
    }
  end

  defp open_range(from, version_type), do: bounded_range(from, "*", version_type)
end
