# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Derivation.Emit do
  @moduledoc """
  Shapes the neutral affected ranges from `Varsel.Cases.Reachability` into the
  CVE `versions[]` blocks each distribution channel publishes.

  `Reachability` reports ranges as raw tag-name bounds (`{from: "v1.7.0", until:
  "v1.7.22"}` / `{from: "OTP-27.0", until: "OTP-27.3.4.3"}`). This module strips
  the tag prefix and, per channel kind, translates and formats:

    * **semver / registry** (`:hex`, `:npm`, plain repo) — bare bounded ranges,
      versionType `"semver"`.
    * **OTP application** (`:otp` on the erlang/otp repo) — each OTP release bound
      translated to the application's own version through
      `Varsel.Cases.Derivation.OtpVersionsTable`, versionType `"otp"`.
    * **OCI** (`:oci`) — one range per `tag_suffixes` flavor
      (`v<version>` / `v<version>-<suffix>`), versionType `"other"`.
    * **git/forge** — a git-SHA range per fix commit from the raw facts, plus (for
      OTP packages) the OTP release block ahead of it.

  Both semver and OTP publish **separate bounded ranges** — one `versions[]`
  object per range (`{version, lessThan, status, versionType}`), never a
  `changes[]` chain: the flat-timeline engine already linearises every version,
  so each affected span is a single half-open interval. An unbounded range
  (affected, never fixed) renders `lessThan: "*"`.
  """

  alias Varsel.Cases.Derivation.OtpVersionsTable
  alias Varsel.Cases.PackageChannel
  alias Varsel.Cases.Reachability

  @type range :: Reachability.range()

  @doc """
  The `versions[]` block for a repo-derived channel: `%{"versions" => [...],
  "issues" => [...]}`. `pending` is added by the caller (it is package-level).
  """
  @spec channel(PackageChannel.t(), [range()], keyword()) :: %{
          required(String.t()) => [map()]
        }
  def channel(channel, ranges, opts) do
    case channel.purl_type do
      :otp ->
        if Keyword.fetch!(opts, :otp_platform?),
          do: otp_app_versions(channel.name, ranges),
          else: %{"versions" => semver_ranges(ranges), "issues" => []}

      :oci ->
        %{"versions" => oci_ranges(channel, ranges), "issues" => []}

      _semver_like ->
        %{"versions" => semver_ranges(ranges), "issues" => []}
    end
  end

  @doc """
  The implicit git/forge entry's `versions[]`: a git-SHA range from the raw facts
  (`[intro_sha, fix_sha)` per fix, released or not), plus the OTP release block
  ahead of it for OTP packages.
  """
  @spec git([String.t()], [String.t()], [range()], keyword()) :: %{
          required(String.t()) => [map()]
        }
  def git(intro_shas, fix_shas, ranges, opts) do
    {git_versions, issues} = git_sha_ranges(intro_shas, fix_shas)

    versions =
      if Keyword.fetch!(opts, :otp_platform?),
        do: otp_release_ranges(ranges) ++ git_versions,
        else: git_versions

    %{"versions" => versions, "issues" => issues}
  end

  @doc """
  cpeApplicability matches from the neutral ranges: each `[from, until)` is one
  non-overlapping `%{versionStartIncluding, versionEndExcluding}` (bare versions).
  A range open below the versioning scheme keeps its concrete lower bound.
  """
  @spec cpe_matches([range()]) :: [map()]
  def cpe_matches(ranges) do
    for range <- ranges do
      # cpe has no "*" sentinel — an open range simply has no upper bound (nil,
      # which the preview drops).
      upper = if range.until == :unbounded, do: nil, else: bare(range.until)
      %{"versionStartIncluding" => bare(range.from), "versionEndExcluding" => upper}
    end
  end

  ## ------------------------------------------------------------ semver / oci

  defp semver_ranges(ranges) do
    for range <- ranges, do: version_object(bare(range.from), bound(range.until), "semver")
  end

  defp oci_ranges(channel, ranges) do
    suffixes = if channel.tag_suffixes == [], do: [nil], else: channel.tag_suffixes

    for suffix <- suffixes, range <- ranges do
      version_object(oci_tag(bare(range.from), suffix), oci_bound(range.until, suffix), "other")
    end
  end

  defp oci_tag(version, nil), do: "v#{version}"
  defp oci_tag(version, suffix), do: "v#{version}-#{suffix}"

  defp oci_bound(:unbounded, _suffix), do: "*"
  defp oci_bound(until, suffix), do: oci_tag(bare(until), suffix)

  ## ------------------------------------------------------------ otp app

  # Translate each OTP release range into the application's own versions, halting
  # on the first release whose app version can't be resolved (reported as issue).
  defp otp_app_versions(app, ranges) do
    Enum.reduce_while(ranges, %{"versions" => [], "issues" => []}, fn range, acc ->
      with {:ok, from} <- OtpVersionsTable.first_shipped_version(bare(range.from), app),
           {:ok, until} <- app_upper_bound(range.until, app) do
        {:cont, %{acc | "versions" => acc["versions"] ++ [version_object(from, until, "otp")]}}
      else
        :error ->
          {:halt, %{"versions" => [], "issues" => ["cannot resolve #{app}'s version for a range"]}}
      end
    end)
  end

  defp app_upper_bound(:unbounded, _app), do: {:ok, "*"}
  defp app_upper_bound(until, app), do: OtpVersionsTable.app_version(bare(until), app)

  # The OTP release block on the git entry: the raw OTP release bounds, bare.
  defp otp_release_ranges(ranges) do
    for range <- ranges, do: version_object(bare(range.from), bound(range.until), "otp")
  end

  ## ------------------------------------------------------------ git

  # The git-SHA range. Commit SHAs are opaque (not linearly orderable), so — like
  # the old git entry — a single fix renders a bounded range and several a
  # `changes[]` chain off the introducing commit. Unreleased fixes still bound the
  # git channel (the commit exists).
  defp git_sha_ranges([], _fix_shas), do: {[], ["the introduced boundary has no commit SHA"]}

  defp git_sha_ranges([intro | _], []), do: {[version_object(intro, "*", "git")], []}

  defp git_sha_ranges([intro | _], [fix]), do: {[version_object(intro, fix, "git")], []}

  defp git_sha_ranges([intro | _], fixes) do
    chain = %{
      "version" => intro,
      "lessThan" => "*",
      "status" => "affected",
      "versionType" => "git",
      "changes" => Enum.map(fixes, &%{"at" => &1, "status" => "unaffected"})
    }

    {[chain], []}
  end

  ## ------------------------------------------------------------ shared

  defp version_object(from, until, version_type) do
    %{
      "version" => from,
      "lessThan" => until,
      "status" => "affected",
      "versionType" => version_type
    }
  end

  defp bound(:unbounded), do: "*"
  defp bound(version), do: bare(version)

  # Strip the tag prefix to the bare version. `OTP_R13B03` keeps its `R…` form.
  defp bare("OTP-" <> rest), do: rest
  defp bare("OTP_" <> rest), do: rest

  defp bare("v" <> <<d, _::binary>> = tag) when d in ?0..?9, do: binary_part(tag, 1, byte_size(tag) - 1)

  defp bare(tag), do: tag
end
