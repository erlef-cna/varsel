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
    * **otp** — OTP release bounds as published (`17.0`, `27.3.4`). A channel
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
  alias Varsel.Cases.Reachability.VersionComparator

  @type range :: Reachability.range()

  # The suffix standing for the undecorated version. A form's comma separated
  # list cannot carry an empty entry — Ash trims it away — so the bare flavor is
  # stored as this marker instead.
  @bare_tag "-"

  # The root (parent-less) commit of erlang/otp: the squashed import its history
  # starts at, so a vulnerability introduced here predates every version the tag
  # set can express.
  @otp_root_commit "84adefa331c4159d432d22840663c38f155cd4c1"

  @doc "The erlang/otp root commit, the start of derivable history."
  @spec otp_root_commit() :: String.t()
  def otp_root_commit, do: @otp_root_commit

  @doc "Whether `sha` is the erlang/otp root commit, the start of derivable history."
  @spec otp_root_commit?(String.t()) :: boolean()
  def otp_root_commit?(sha), do: sha == @otp_root_commit

  @doc """
  The `versions[]` block for a repo-derived channel: `%{"versions" => [...],
  "issues" => [...]}`. `pending` is added by the caller (it is package-level).

  `opts` carries the boundary facts the git version type needs
  (`:intro_shas` / `:fix_shas`) and whether the introducing commit is the OTP
  root with no explicit version to place it (`:otp_root_intro?`).
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

        other ->
          versions(channel, other, ranges, Keyword.get(opts, :boundaries))
      end

    prepend_root_sentinel(result, sentinel_for(channel, version_type, ranges, opts))
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

  A range reaching back to the start of derivable history (`otp_root_intro?`)
  drops its lower bound instead of naming the release there, matching how NVD
  writes OTP's lowest affected line (`{versionEndExcluding: "23.3.4.15"}`, no
  start). CPE has no way to say "unknown", so the span the `versions[]` sentinel
  marks `unknown` is simply left unbounded below here — CPE version comparison is
  consumer-defined, so naming the lowest release as a bound would be a stronger
  claim than we can derive.
  """
  @spec cpe_matches([range()], keyword()) :: [map()]
  def cpe_matches(ranges, opts \\ []) do
    # Reachability emits ranges in ascending release order, so the first is the
    # lowest.
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

  ## ------------------------------------------------------------ versions

  # A bounded `version → lessThan` range asserts that its bounds have an order.
  # That holds for semver, dates and image tags, and not for a scheme whose
  # versions branch: OTP's 27.3.4.15 and 28.0 each carry changes the other
  # lacks, so a range spanning them claims something untrue. Those schemes state
  # the same facts as one open entry with a transition per fix, which the schema
  # resolves by applying every transition at or below the version asked about —
  # the fixes on that version's own line, and no others.
  defp versions(channel, version_type, ranges, boundaries) do
    vocabulary = vocabulary(channel, version_type)

    if VersionComparator.total_order?(version_type) do
      flat_versions(channel, version_type, ranges, vocabulary)
    else
      status_change_versions(channel, version_type, ranges, boundaries, vocabulary)
    end
  end

  defp status_change_versions(channel, version_type, ranges, boundaries, vocabulary) do
    case status_change_entry(channel, version_type, boundaries, vocabulary) do
      nil -> flat_versions(channel, version_type, ranges, vocabulary)
      entry -> %{"versions" => [entry], "issues" => []}
    end
  end

  # How a channel names the versions it publishes. A `pkg:otp` channel
  # publishing OTP versions names one application, whose own versions differ
  # from the release's; every other channel already speaks its package's
  # vocabulary.
  #
  # The two ends resolve differently. A lower bound falls forward to the first
  # release that ships the application, since a flaw introduced before the
  # application existed still reaches it once it does. An upper bound is exact:
  # a fix in a release that does not ship the application says nothing about
  # that application, and answering with a later version would invent a fix.
  defp vocabulary(%{purl_type: "otp", name: app}, :otp) when is_binary(app) do
    %{
      lower: &app_first_version(&1, app),
      upper: &OtpVersionsTable.app_version(&1, app),
      issue: "cannot resolve #{app}'s version for a range"
    }
  end

  defp vocabulary(_channel, _version_type) do
    %{lower: &{:ok, &1}, upper: &{:ok, &1}, issue: nil}
  end

  defp flat_versions(channel, version_type, ranges, vocabulary) do
    type = to_string(version_type)

    ranges
    |> Enum.reduce_while([], fn range, acc ->
      case translate_range(range, vocabulary) do
        {:ok, translated} -> {:cont, [decorated_ranges(channel, [translated], type) | acc]}
        :error -> {:halt, :error}
      end
    end)
    |> case do
      :error -> %{"versions" => [], "issues" => [vocabulary.issue]}
      acc -> %{"versions" => acc |> Enum.reverse() |> List.flatten(), "issues" => []}
    end
  end

  defp translate_range(%{from: from, until: until}, vocabulary) do
    with {:ok, from} <- vocabulary.lower.(bare(from)),
         {:ok, until} <- translate_upper(until, vocabulary) do
      {:ok, %{from: from, until: until}}
    end
  end

  defp translate_upper(:unbounded, _vocabulary), do: {:ok, :unbounded}
  defp translate_upper(until, vocabulary), do: vocabulary.upper.(bare(until))

  defp status_change_entry(_channel, _version_type, nil, _vocabulary), do: nil
  defp status_change_entry(_channel, _version_type, %{introduced: nil}, _vocabulary), do: nil
  defp status_change_entry(_channel, _version_type, %{fixed: []}, _vocabulary), do: nil
  defp status_change_entry(_channel, _version_type, %{open?: false}, _vocabulary), do: nil

  # One fix needs no transition: `lessThan` states the same span, and states it
  # better. An open entry claims every version above the bound, including ones
  # not released yet, and a single fix on a branch can never close a line that
  # does not exist yet, so the open form would report tomorrow's release
  # affected. The bounded form claims only what was derived.
  defp status_change_entry(_channel, _version_type, %{fixed: [_only_one]}, _vocabulary), do: nil

  defp status_change_entry(channel, version_type, boundaries, vocabulary) do
    %{introduced: introduced, fixed: fixed} = boundaries
    prefix = channel.tag_prefix || ""

    with {:ok, from} <- vocabulary.lower.(bare(introduced)),
         {:ok, changes} <- translate_all(fixed, vocabulary) do
      %{
        "version" => prefix <> from,
        "lessThan" => "*",
        "status" => "affected",
        "versionType" => to_string(version_type),
        "changes" => Enum.map(changes, &%{"at" => prefix <> &1, "status" => "unaffected"})
      }
    else
      :error -> nil
    end
  end

  # Each fix is an upper bound of the span it closes, so all of them resolve
  # exactly.
  defp translate_all(versions, vocabulary) do
    versions
    |> Enum.reduce_while([], fn version, acc ->
      case vocabulary.upper.(bare(version)) do
        {:ok, translated} -> {:cont, [translated | acc]}
        :error -> {:halt, :error}
      end
    end)
    |> case do
      :error -> :error
      acc -> {:ok, Enum.reverse(acc)}
    end
  end

  # The application's version where an affected span opens. `tftp` split out of
  # `inets` long after some flaws were introduced, so a release predating the
  # application resolves to the first version that ships it.
  defp app_first_version(version, app) do
    if version == VersionComparator.zero(),
      do: {:ok, version},
      else: OtpVersionsTable.first_shipped_version(version, app)
  end

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

  # The `unknown` range below the first affected release, prepended when the vuln
  # was introduced at the OTP root commit: erlang/otp's history starts at that
  # squashed import, so anything earlier is underivable rather than unaffected.
  #
  # The bound must not overlap the first range. CVE Record Format 5.1 resolves a
  # version from the FIRST entry covering it, and the sentinel is prepended, so
  # any overlap answers `unknown` for a version the ranges call affected.
  #
  # Only otp-versioned channels get one: a git channel is versioned in commit
  # SHAs and no commit precedes the root commit, and semver channels of other
  # products never see it.
  defp sentinel_for(channel, :otp, ranges, opts) do
    if Keyword.get(opts, :otp_root_intro?, false), do: otp_sentinel(channel, ranges)
  end

  defp sentinel_for(_channel, _version_type, _ranges, _opts), do: nil

  defp otp_sentinel(_channel, []), do: nil

  # Through the channel's own vocabulary, so the sentinel closes exactly where
  # the first range opens.
  defp otp_sentinel(channel, [%{from: from} | _]) do
    vocabulary = vocabulary(channel, :otp)

    case vocabulary.lower.(bare(from)) do
      {:ok, version} -> unknown_range(version, "otp")
      :error -> nil
    end
  end

  defp unknown_range(upper, version_type) do
    %{
      "version" => VersionComparator.zero(),
      "lessThan" => upper,
      "status" => "unknown",
      "versionType" => version_type
    }
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

  # Strip the tag prefix to the bare version.
  defp bare(:unbounded), do: :unbounded
  defp bare("OTP-" <> rest), do: rest
  defp bare("OTP_" <> rest), do: rest

  defp bare("v" <> <<d, _::binary>> = tag) when d in ?0..?9, do: binary_part(tag, 1, byte_size(tag) - 1)

  defp bare(tag), do: tag
end
