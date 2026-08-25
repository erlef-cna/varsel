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
     neutral ranges into each channel's `versions[]`, in the vocabulary that
     channel publishes in (semver, OTP release or per-application versions via
     `OtpVersionsTable`, or commit SHAs for the repository channel).
  2. Channel-scoped events (`package_channel_id` set, e.g. date boundaries on a
     `:service` channel) replace the repo derivation for that channel and are
     used verbatim.
  3. A fixed commit contained in no release is *pending*: it still bounds the
     git-versioned channel, is reported in `"pending"`, and blocks publishing
     unless the package allows unreleased fixes. An introducing commit
     contained in no release is reported in `"unreleased_intros"` and blocks
     the same way unless the package allows unreleased intros.

  ## Result shape (JSON-safe, cached in jsonb, all string keys)

      %{
        "channels" => %{<channel-uuid> => %{"versions" => [...],
                                            "pending" => [...],
                                            "unreleased_intros" => [...],
                                            "issues" => [...]}},
        # either bound is nil when the range is open on that side (the preview drops it)
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

    {intro_shas, fix_shas} = boundary_shas(global_events)

    emit_opts = [
      intro_shas: intro_shas,
      fix_shas: fix_shas,
      otp_root_intro?: platform.kind == :otp and unresolved_otp_root_intro?(global_events)
    ]

    channels =
      Map.new(package.channels, fn channel ->
        events = Enum.filter(scoped_events, &(&1.package_channel_id == channel.id))
        {channel.id, derive_channel(channel, reach, events, emit_opts, pending)}
      end)

    {:ok,
     %{
       "channels" => channels,
       "cpe_matches" => Emit.cpe_matches(reach.ranges, emit_opts),
       "call_outs" => reach.call_outs,
       "issues" => reach.issues
     }}
  end

  # Run the reachability engine over the package's global commit facts. Without a
  # repo_url (or without commit facts) there is nothing to resolve.
  defp reachability(%{repo_url: nil}, _platform, _events), do: empty_reachability()

  defp reachability(package, platform, events) do
    {intros, fixes} = boundary_shas(events)
    explicit = explicit_versions(events)

    if intros == [] and fixes == [] and explicit == [] do
      empty_reachability()
    else
      case Reachability.derive(package.repo_url, intros, fixes,
             comparator: platform.kind,
             include_prereleases: package.include_prereleases,
             explicit_versions: explicit
           ) do
        {:ok, result} ->
          result

        {:error, reason} ->
          %{empty_reachability() | issues: ["cannot resolve versions: #{inspect(reason)}"]}
      end
    end
  end

  defp empty_reachability do
    %{
      ranges: [],
      call_outs: [],
      open?: false,
      pending_fixes: [],
      unreleased_intros: [],
      issues: []
    }
  end

  # Explicit `{event, version}` boundaries from the global events — releases the
  # repository never tagged, which git containment therefore cannot place. An
  # event may carry both a SHA and a version: the SHA bounds the git entry, the
  # version names the untagged release for the versioned channels.
  defp explicit_versions(events) do
    for %{version: version} = event <- events, is_binary(version), do: {event.event, version}
  end

  # Introduced / fixed commit SHAs from the global (non-channel-scoped) events.
  defp boundary_shas(events) do
    {intros, fixes} =
      events
      |> Enum.filter(& &1.commit_sha)
      |> Enum.split_with(&(&1.event == :introduced))

    {Enum.map(intros, & &1.commit_sha), Enum.map(fixes, & &1.commit_sha)}
  end

  # Whether the OTP root commit stands as the introduced boundary with nothing
  # else to place it: an event pairing that commit with an explicit version
  # (e.g. "0", "R1A") names where the range truly starts, so the span below it
  # is resolved rather than unknown.
  defp unresolved_otp_root_intro?(events) do
    Enum.any?(events, fn event ->
      event.event == :introduced and is_binary(event.commit_sha) and
        Emit.otp_root_commit?(event.commit_sha) and is_nil(event.version)
    end)
  end

  ## --------------------------------------------------------------- channels

  defp derive_channel(channel, reach, scoped_events, emit_opts, pending) do
    cond do
      scoped_events != [] ->
        derive_scoped_channel(channel, scoped_events)

      channel.kind == :service ->
        %{
          "versions" => [],
          "pending" => [],
          "unreleased_intros" => [],
          "issues" => ["service channels need channel-scoped version events"]
        }

      true ->
        channel
        |> Emit.channel(reach.ranges, emit_opts)
        |> Map.put("pending", pending)
        |> Map.put("unreleased_intros", reach.unreleased_intros)
    end
  end

  # Channel-scoped explicit events: used verbatim as one range.
  defp derive_scoped_channel(channel, events) do
    intro = Enum.find(events, &(&1.event == :introduced))
    fixes = Enum.filter(events, &(&1.event == :fixed))
    version_type = channel |> Emit.version_type() |> to_string()

    cond do
      intro == nil ->
        %{
          "versions" => [],
          "pending" => [],
          "unreleased_intros" => [],
          "issues" => ["channel-scoped events lack an introduced boundary"]
        }

      fixes == [] ->
        %{
          "versions" => [open_range(boundary_value(intro), version_type)],
          "pending" => [],
          "unreleased_intros" => [],
          "issues" => []
        }

      true ->
        versions =
          for fix <- fixes,
              do: bounded_range(boundary_value(intro), boundary_value(fix), version_type)

        %{"versions" => versions, "pending" => [], "unreleased_intros" => [], "issues" => []}
    end
  end

  defp boundary_value(%{version: version}) when not is_nil(version), do: version
  defp boundary_value(%{commit_sha: sha}), do: sha

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
