# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Derivation.Platform do
  @moduledoc """
  Tag and version conventions of a package's release process — the knobs the
  derivation pipeline needs to turn commit SHAs into version boundaries
  (a port of `gen-affected`'s platform configs in the cna repository).

  Two kinds exist:

  * `:otp` — Erlang/OTP: `OTP-` / legacy `OTP_R` tag prefixes, pre-releases
    don't count as shipped, backports group per major release line.
  * `:semver` — everything else: `v`-or-bare tags, pre-releases count as
    shipped (semver ecosystem norm, GHSAs cover RCs), backports group per
    `{major, minor}` line.
  """

  @enforce_keys [:kind, :tag_prefixes, :pre_releases_are_stable]
  defstruct [:kind, :tag_prefixes, :pre_releases_are_stable]

  @type kind :: :otp | :semver
  @type t :: %__MODULE__{
          kind: kind(),
          tag_prefixes: [{String.t(), :modern | :legacy}],
          pre_releases_are_stable: boolean()
        }

  @type classified_tag :: {kind :: :modern | :legacy, tag :: String.t(), bare :: String.t()}

  @doc "Picks the platform for an affected package based on its channels."
  @spec for_package(Varsel.Cases.AffectedPackage.t(), [Varsel.Cases.PackageChannel.t()]) :: t()
  def for_package(package, channels) do
    otp? =
      Enum.any?(channels, &(&1.purl_type == :otp)) or
        (package.repo_url || "") =~ ~r{github\.com/erlang/otp}

    if otp? do
      %__MODULE__{
        kind: :otp,
        tag_prefixes: [{"OTP-", :modern}, {"OTP_R", :legacy}],
        pre_releases_are_stable: false
      }
    else
      %__MODULE__{
        kind: :semver,
        tag_prefixes: [{"v", :modern}, {"", :modern}],
        pre_releases_are_stable: true
      }
    end
  end

  @doc """
  Classifies a repository tag name against the platform's prefixes.
  Returns nil for tags that are not release versions (e.g. "latest").
  """
  @spec classify_tag(t(), String.t()) :: classified_tag() | nil
  def classify_tag(platform, name) do
    Enum.find_value(platform.tag_prefixes, &classify_with_prefix(&1, name))
  end

  defp classify_with_prefix({prefix, kind}, name) do
    with true <- String.starts_with?(name, prefix),
         bare = String.replace_prefix(name, prefix, ""),
         true <- version_like?(kind, bare) do
      {kind, name, bare}
    else
      false -> nil
    end
  end

  # A bare tag must start with a digit to count as a release version — stops
  # the semver empty-prefix fallback from sweeping in tags like "latest".
  defp version_like?(:legacy, _bare), do: true
  defp version_like?(:modern, <<c, _::binary>>) when c in ?0..?9, do: true
  defp version_like?(_kind, _bare), do: false

  @doc """
  The earliest release tag among the given repository tag names — the tag a
  boundary commit first shipped in. Legacy (pre-semver OTP_R) tags win when
  present; pre-release tags only count where the platform treats them as
  shipped. Returns nil when no tag qualifies (fix not yet released).
  """
  @spec earliest_tag(t(), [String.t()]) :: String.t() | nil
  def earliest_tag(platform, tag_names) do
    tags = tag_names |> Enum.map(&classify_tag(platform, &1)) |> Enum.reject(&is_nil/1)

    legacy = Enum.filter(tags, &match?({:legacy, _, _}, &1))
    modern = Enum.filter(tags, &match?({:modern, _, _}, &1))

    modern_candidates =
      if platform.pre_releases_are_stable,
        do: modern,
        else: Enum.reject(modern, fn {_, _, bare} -> pre_release?(bare) end)

    cond do
      legacy != [] ->
        legacy |> Enum.min_by(fn {_, _, bare} -> bare end) |> elem(1)

      modern_candidates != [] ->
        modern_candidates |> Enum.min_by(fn {_, _, bare} -> parse_version(bare) end) |> elem(1)

      modern != [] ->
        # Only pre-release tags exist and the platform excludes them; report
        # the earliest pre-release rather than nothing.
        modern |> Enum.min_by(fn {_, _, bare} -> parse_version(bare) end) |> elem(1)

      true ->
        nil
    end
  end

  defp pre_release?(version), do: String.contains?(version, "-")

  @doc "Strips the platform prefix from a tag (legacy OTP_R tags render as R<series>)."
  @spec strip_prefix(t(), String.t()) :: String.t()
  def strip_prefix(platform, tag) do
    Enum.find_value(platform.tag_prefixes, tag, &strip_with_prefix(&1, tag))
  end

  defp strip_with_prefix({prefix, kind}, tag) do
    if String.starts_with?(tag, prefix) do
      bare = String.replace_prefix(tag, prefix, "")
      if kind == :legacy, do: "R" <> bare, else: bare
    end
  end

  @doc """
  The release line a version belongs to, for grouping backported fixes:
  the major for `:otp`, `{major, minor}` for `:semver`. nil for legacy tags.
  """
  @spec group_key(t(), String.t()) :: term() | nil
  def group_key(%{kind: :otp}, "R" <> _legacy), do: nil

  def group_key(%{kind: :otp}, version) do
    version |> parse_version() |> elem(0) |> List.first()
  end

  def group_key(%{kind: :semver}, version) do
    case version |> parse_version() |> elem(0) do
      [major, minor | _] -> {major, minor}
      [major] -> {major, 0}
      _ -> nil
    end
  end

  @doc "Human label of the version a release line starts at (for cpe chaining)."
  @spec group_label(t(), term()) :: String.t()
  def group_label(%{kind: :otp}, major), do: "#{major}.0"
  def group_label(%{kind: :semver}, {major, minor}), do: "#{major}.#{minor}.0"

  @doc "Successor of a release-line key (the line the next fix range starts at)."
  @spec next_key(t(), term()) :: term()
  def next_key(%{kind: :otp}, major), do: major + 1
  def next_key(%{kind: :semver}, {major, minor}), do: {major, minor + 1}

  @doc "True for boundaries so old they predate the versioning scheme (legacy OTP_R intros)."
  @spec legacy_version?(t(), String.t()) :: boolean()
  def legacy_version?(%{kind: :otp}, "R" <> _rest), do: true
  def legacy_version?(_platform, _version), do: false

  @doc """
  Sortable representation of a version string: numeric parts, with released
  versions ranking above pre-releases of the same number.
  """
  @spec parse_version(String.t()) :: {[integer()], 0 | 1, String.t()}
  def parse_version(version) do
    {numeric, suffix} =
      case String.split(version, "-", parts: 2) do
        [n] -> {n, ""}
        [n, s] -> {n, s}
      end

    nums =
      numeric
      |> String.split(".")
      |> Enum.map(fn part ->
        case Integer.parse(part) do
          {i, ""} -> i
          _ -> 0
        end
      end)

    suffix_rank = if suffix == "", do: 1, else: 0
    {nums, suffix_rank, suffix}
  end

  @doc "Descending sort key for release-line keys (newest line first)."
  @spec sort_desc(term()) :: term()
  def sort_desc(key) when is_integer(key), do: -key
  def sort_desc({major, minor}), do: {-major, -minor}
  def sort_desc(_key), do: 0
end
