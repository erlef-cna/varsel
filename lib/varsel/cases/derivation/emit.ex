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
    * **OTP release** (`:sid` on the erlang/otp repo) — the OTP release bounds as
      published (`R13B03`, `27.3.4`), versionType `"otp"`.
    * **OTP application** (`:otp` on the erlang/otp repo) — each OTP release bound
      translated to the application's own version through
      `Varsel.Cases.Derivation.OtpVersionsTable`, versionType `"otp"`.
    * **OCI** (`:oci`) — one range per `tag_suffixes` flavor
      (`<tag_prefix><version>` / `<tag_prefix><version>-<suffix>`), versionType
      `"other"`. A `"-"` suffix emits the bare tag, so a repo tagging both
      `1.2.3` and `1.2.3-special` lists `["-", "special"]`.
    * **git/forge** — a git-SHA range per fix commit from the raw facts, and
      nothing else: release versions belong to the release channel.

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

  # The suffix standing for the unsuffixed image tag. A form's comma separated
  # list cannot carry an empty entry — Ash trims it away — so the bare-tag
  # flavor is stored as this marker instead.
  @bare_tag "-"

  # The root (parent-less) commit of erlang/otp — the R13B03 import that squashed
  # all pre-R13B03 history. A vulnerability introduced *at* this commit predates
  # every version our tag set can express, so we prepend an `unknown` sentinel
  # range for the pre-R13B03 era rather than claiming to have derived it.
  @otp_root_commit "84adefa331c4159d432d22840663c38f155cd4c1"
  @first_otp_tag "R13B03"

  @doc "Whether `sha` is the erlang/otp root commit (the pre-R13B03 boundary)."
  @spec otp_root_commit?(String.t()) :: boolean()
  def otp_root_commit?(sha), do: sha == @otp_root_commit

  @doc """
  The `versions[]` block for a repo-derived channel: `%{"versions" => [...],
  "issues" => [...]}`. `pending` is added by the caller (it is package-level).
  """
  @spec channel(PackageChannel.t(), [range()], keyword()) :: %{
          required(String.t()) => [map()]
        }
  def channel(channel, ranges, opts) do
    result =
      case channel.purl_type do
        :otp ->
          if Keyword.fetch!(opts, :otp_platform?),
            do: otp_app_versions(channel.name, ranges),
            else: %{"versions" => semver_ranges(ranges), "issues" => []}

        :sid ->
          if Keyword.fetch!(opts, :otp_platform?),
            do: %{"versions" => otp_release_ranges(ranges), "issues" => []},
            else: %{"versions" => semver_ranges(ranges), "issues" => []}

        :oci ->
          %{"versions" => oci_ranges(channel, ranges), "issues" => []}

        _semver_like ->
          %{"versions" => semver_ranges(ranges), "issues" => []}
      end

    prepend_root_sentinel(result, sentinel_for(channel, opts))
  end

  @doc """
  The implicit git/forge entry's `versions[]`: a git-SHA range from the raw facts
  (`[intro_sha, fix_sha)` per fix, released or not).

  Commit SHAs only — the entry says nothing about release versions (those are the
  release channel's), and it carries no pre-root `unknown` sentinel: erlang/otp's
  history *starts* at the root commit, so there is no earlier commit for such a
  range to cover.
  """
  @spec git([String.t()], [String.t()], keyword()) :: %{
          required(String.t()) => [map()]
        }
  def git(intro_shas, fix_shas, _opts) do
    {versions, issues} = git_sha_ranges(intro_shas, fix_shas)

    %{"versions" => versions, "issues" => issues}
  end

  @doc """
  cpeApplicability matches from the neutral ranges: each `[from, until)` is one
  non-overlapping `%{versionStartIncluding, versionEndExcluding}` (bare versions).

  A range reaching back to the start of derivable history (`otp_root_intro?` —
  the pre-R13B03 era) drops its lower bound instead of naming `R13B03`, matching
  how NVD writes OTP's lowest affected line (`{versionEndExcluding: "23.3.4.15"}`,
  no start). CPE has no way to say "unknown", so the pre-R13B03 span the
  `versions[]` sentinel marks `unknown` is simply left unbounded below here — CPE
  version comparison is consumer-defined and R-series tags do not collate against
  numeric ones, so naming `R13B03` as a bound would be both unmatched and a
  stronger claim than we can derive.
  """
  @spec cpe_matches([range()], keyword()) :: [map()]
  def cpe_matches(ranges, opts \\ []) do
    # Reachability emits ranges in ascending release order, so the first one is
    # the lowest — the only one that can reach back past R13B03.
    drop_lower_bound? = otp_root_intro?(opts)

    for {range, index} <- Enum.with_index(ranges) do
      # cpe has no "*" sentinel — an open range simply has no upper bound (nil,
      # which the preview drops).
      upper = if range.until == :unbounded, do: nil, else: bare(range.until)
      lower = if drop_lower_bound? and index == 0, do: nil, else: bare(range.from)

      %{"versionStartIncluding" => lower, "versionEndExcluding" => upper}
    end
  end

  ## ------------------------------------------------------------ semver / oci

  defp semver_ranges(ranges) do
    for range <- ranges, do: version_object(bare(range.from), bound(range.until), "semver")
  end

  defp oci_ranges(channel, ranges) do
    prefix = channel.tag_prefix || ""
    suffixes = if channel.tag_suffixes == [], do: [@bare_tag], else: channel.tag_suffixes

    for suffix <- suffixes, range <- ranges do
      version_object(
        oci_tag(prefix, bare(range.from), suffix),
        oci_bound(prefix, range.until, suffix),
        "other"
      )
    end
  end

  defp oci_tag(prefix, version, @bare_tag), do: "#{prefix}#{version}"
  defp oci_tag(prefix, version, suffix), do: "#{prefix}#{version}-#{suffix}"

  defp oci_bound(_prefix, :unbounded, _suffix), do: "*"
  defp oci_bound(prefix, until, suffix), do: oci_tag(prefix, bare(until), suffix)

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

  ## ------------------------------------------------------------ root sentinel

  # The `unknown` range covering the pre-R13B03 era, prepended when the vuln was
  # introduced at the OTP root commit — the squashed import that erlang/otp's
  # history starts at, so anything earlier is genuinely underivable rather than
  # unaffected. `nil` (no sentinel) otherwise.
  #
  #   * otp app channel     -> {version:"0", lessThan:<app vsn at R13B03>, unknown}
  #   * otp release channel -> {version:"0", lessThan:"R13B03", unknown}
  #   * plain semver        -> no sentinel (the root commit only exists in OTP)
  #
  # The git entry deliberately gets none: it is versioned in commit SHAs, and no
  # commit precedes the root commit.
  defp sentinel_for(%{purl_type: :otp, name: app}, opts) do
    if otp_root_intro?(opts) do
      case OtpVersionsTable.app_version(@first_otp_tag, app) do
        {:ok, version} -> unknown_range(version, "otp")
        :error -> nil
      end
    end
  end

  defp sentinel_for(%{purl_type: :sid}, opts) do
    if otp_root_intro?(opts), do: unknown_range(@first_otp_tag, "otp")
  end

  defp sentinel_for(_channel, _opts), do: nil

  defp otp_root_intro?(opts) do
    Keyword.get(opts, :otp_root_intro?, false) and Keyword.get(opts, :otp_platform?, false)
  end

  defp unknown_range(upper, version_type) do
    %{"version" => "0", "lessThan" => upper, "status" => "unknown", "versionType" => version_type}
  end

  defp prepend_root_sentinel(result, nil), do: result

  defp prepend_root_sentinel(%{"versions" => versions} = result, sentinel) do
    %{result | "versions" => [sentinel | versions]}
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
