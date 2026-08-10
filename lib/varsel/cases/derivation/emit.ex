# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Derivation.Emit do
  @moduledoc """
  Shapes the neutral affected ranges from `Varsel.Cases.Reachability` into the
  CVE `versions[]` blocks each distribution channel publishes.

  `Reachability` reports ranges as raw tag-name bounds (`{from: "v1.7.0", until:
  "v1.7.22"}` / `{from: "OTP-27.0", until: "OTP-27.3.4.3"}`). This module strips
  the tag prefix and formats each bound in the channel's *version type* — the
  vocabulary it publishes in, stored on the channel rather than guessed from its
  purl type:

    * **semver** — bare bounded ranges.
    * **otp** — OTP release bounds as published (`R13B03`, `27.3.4`). A channel
      naming a single OTP application (`pkg:otp/<app>`) has each bound
      translated to that application's own version through
      `Varsel.Cases.Derivation.OtpVersionsTable`.
    * **git** — a commit-SHA range per fix commit, from the raw boundary facts:
      commit SHAs are opaque, so no release version appears here.
    * **date** / **other** — the bounds verbatim.

  Every channel then applies its tag decoration: `tag_prefix` prepended and one
  range emitted per `tag_suffixes` flavor (`<prefix><version>-<suffix>`). A
  `"-"` suffix emits the bare version, so a channel publishing both `1.2.3` and
  `1.2.3-special` lists `["-", "special"]`; an empty list emits the version
  alone.

  Ranges are published as **separate bounded ranges** — one `versions[]` object
  per range (`{version, lessThan, status, versionType}`), never a `changes[]`
  chain: the flat-timeline engine already linearises every version, so each
  affected span is a single half-open interval. An unbounded range (affected,
  never fixed) renders `lessThan: "*"`. The git type is the exception: SHAs have
  no order, so several fixes render as a `changes[]` chain off the introducing
  commit.
  """

  alias Varsel.Cases.Derivation.OtpVersionsTable
  alias Varsel.Cases.PackageChannel
  alias Varsel.Cases.PackageChannel.PurlType
  alias Varsel.Cases.Reachability

  @type range :: Reachability.range()

  # The suffix standing for the undecorated version. A form's comma separated
  # list cannot carry an empty entry — Ash trims it away — so the bare flavor is
  # stored as this marker instead.
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

  `opts` carries the boundary facts the git version type needs
  (`:intro_shas` / `:fix_shas`) and whether the introducing commit is the OTP
  root (`:otp_root_intro?`).
  """
  @spec channel(PackageChannel.t(), [range()], keyword()) :: %{
          required(String.t()) => [map()]
        }
  def channel(channel, ranges, opts) do
    version_type = version_type(channel)

    result =
      case version_type do
        :git ->
          git(Keyword.get(opts, :intro_shas, []), Keyword.get(opts, :fix_shas, []))

        :otp ->
          otp_versions(channel, ranges)

        other ->
          %{"versions" => decorated_ranges(channel, ranges, to_string(other)), "issues" => []}
      end

    prepend_root_sentinel(result, sentinel_for(channel, version_type, opts))
  end

  @doc """
  The version type a channel publishes in: its own when set, else its purl
  type's default. Service channels are always dated.
  """
  @spec version_type(PackageChannel.t() | map()) :: atom()
  def version_type(%{kind: :service}), do: :date
  def version_type(%{version_type: version_type}) when not is_nil(version_type), do: version_type
  def version_type(channel), do: PurlType.default_version_type(channel.purl_type)

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
    drop_lower_bound? = Keyword.get(opts, :otp_root_intro?, false)

    for {range, index} <- Enum.with_index(ranges) do
      # cpe has no "*" sentinel — an open range simply has no upper bound (nil,
      # which the preview drops).
      upper = if range.until == :unbounded, do: nil, else: bare(range.until)
      lower = if drop_lower_bound? and index == 0, do: nil, else: bare(range.from)

      %{"versionStartIncluding" => lower, "versionEndExcluding" => upper}
    end
  end

  ## ------------------------------------------------------------ decoration

  # Every non-git range passes through the channel's tag decoration: one range
  # per flavor, each bound prefixed and suffixed. No suffixes means the bare
  # version, which is what most channels publish.
  defp decorated_ranges(channel, ranges, version_type) do
    prefix = channel.tag_prefix || ""
    suffixes = if channel.tag_suffixes in [nil, []], do: [@bare_tag], else: channel.tag_suffixes

    for suffix <- suffixes, range <- ranges do
      version_object(
        decorate(prefix, bare(range.from), suffix),
        decorated_bound(prefix, range.until, suffix),
        version_type
      )
    end
  end

  defp decorate(prefix, version, @bare_tag), do: "#{prefix}#{version}"
  defp decorate(prefix, version, suffix), do: "#{prefix}#{version}-#{suffix}"

  defp decorated_bound(_prefix, :unbounded, _suffix), do: "*"
  defp decorated_bound(prefix, until, suffix), do: decorate(prefix, bare(until), suffix)

  ## ------------------------------------------------------------ otp

  # A pkg:otp channel names one application, whose own versions differ from the
  # release's; any other otp-versioned channel publishes the release versions.
  defp otp_versions(%{purl_type: "otp", name: app} = channel, ranges) when is_binary(app) do
    otp_app_versions(channel, app, ranges)
  end

  defp otp_versions(channel, ranges) do
    %{"versions" => decorated_ranges(channel, ranges, "otp"), "issues" => []}
  end

  # Translate each OTP release range into the application's own versions, halting
  # on the first release whose app version can't be resolved (reported as issue).
  defp otp_app_versions(channel, app, ranges) do
    Enum.reduce_while(ranges, %{"versions" => [], "issues" => []}, fn range, acc ->
      with {:ok, from} <- OtpVersionsTable.first_shipped_version(bare(range.from), app),
           {:ok, until} <- app_upper_bound(range.until, app) do
        versions =
          acc["versions"] ++ decorated_ranges(channel, [%{from: from, until: until}], "otp")

        {:cont, %{acc | "versions" => versions}}
      else
        :error ->
          {:halt, %{"versions" => [], "issues" => ["cannot resolve #{app}'s version for a range"]}}
      end
    end)
  end

  defp app_upper_bound(:unbounded, _app), do: {:ok, :unbounded}
  defp app_upper_bound(until, app), do: OtpVersionsTable.app_version(bare(until), app)

  ## ------------------------------------------------------------ git

  # The git-SHA range. Commit SHAs are opaque (not linearly orderable), so a
  # single fix renders a bounded range and several a `changes[]` chain off the
  # introducing commit. Unreleased fixes still bound a git channel: the commit
  # exists whether or not a release contains it.
  defp git([], _fix_shas), do: %{"versions" => [], "issues" => ["the introduced boundary has no commit SHA"]}

  defp git([intro | _], []), do: %{"versions" => [version_object(intro, "*", "git")], "issues" => []}

  defp git([intro | _], [fix]), do: %{"versions" => [version_object(intro, fix, "git")], "issues" => []}

  defp git([intro | _], fixes) do
    chain = %{
      "version" => intro,
      "lessThan" => "*",
      "status" => "affected",
      "versionType" => "git",
      "changes" => Enum.map(fixes, &%{"at" => &1, "status" => "unaffected"})
    }

    %{"versions" => [chain], "issues" => []}
  end

  ## ------------------------------------------------------------ root sentinel

  # The `unknown` range covering the pre-R13B03 era, prepended when the vuln was
  # introduced at the OTP root commit — the squashed import that erlang/otp's
  # history starts at, so anything earlier is genuinely underivable rather than
  # unaffected. `nil` (no sentinel) otherwise.
  #
  #   * otp application channel -> {version:"0", lessThan:<app vsn at R13B03>, unknown}
  #   * otp release channel     -> {version:"0", lessThan:"R13B03", unknown}
  #
  # Only otp-versioned channels get one: a git channel is versioned in commit
  # SHAs and no commit precedes the root commit, and semver channels of other
  # products never see it.
  defp sentinel_for(channel, :otp, opts) do
    if Keyword.get(opts, :otp_root_intro?, false), do: otp_sentinel(channel)
  end

  defp sentinel_for(_channel, _version_type, _opts), do: nil

  defp otp_sentinel(%{purl_type: "otp", name: app}) when is_binary(app) do
    case OtpVersionsTable.app_version(@first_otp_tag, app) do
      {:ok, version} -> unknown_range(version, "otp")
      :error -> nil
    end
  end

  defp otp_sentinel(_channel), do: unknown_range(@first_otp_tag, "otp")

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

  # Strip the tag prefix to the bare version. `OTP_R13B03` keeps its `R…` form.
  defp bare(:unbounded), do: :unbounded
  defp bare("OTP-" <> rest), do: rest
  defp bare("OTP_" <> rest), do: rest

  defp bare("v" <> <<d, _::binary>> = tag) when d in ?0..?9, do: binary_part(tag, 1, byte_size(tag) - 1)

  defp bare(tag), do: tag
end
