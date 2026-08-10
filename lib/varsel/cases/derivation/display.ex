# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Derivation.Display do
  @moduledoc """
  Reads an affected package's *cached* derivation into display text.

  Deriving the affected versions of a package means walking its repository and
  the registries it publishes to, so the result is computed elsewhere and
  cached on the package (`AffectedPackage.derivation_cache`); this module only
  reads that cache.

  Nothing here is authoritative — publishing recomputes the versions from the
  boundary facts, so a stale or missing cache degrades to a label, never to
  wrong published data.

  Everything returned is display text: labels, notes and timeline rows, with
  commit SHAs shortened for the tables they render in.
  """

  alias Varsel.Cases.Case.Calculations.Preview.Channel

  @renderable_version_types ~w(semver otp date)

  @doc """
  Every channel of a package paired with what its derivation produced:

      [{channel, %{versions:, pending?:, issues:, timeline:}}]

  `versions` is the raw CVE `versions[]` the cache holds, ready for the same
  components the published record renders through. `timeline` is nil for a
  channel whose versions cannot be laid on a line (commit SHAs).
  """
  @spec channel_derivations(struct()) :: [{struct(), map()}]
  def channel_derivations(package) do
    for channel <- package.channels do
      derivation = channel_derivation(package.derivation_cache, channel.id) || %{}

      {channel,
       %{
         versions: derivation["versions"] || [],
         pending?: (derivation["pending"] || []) != [],
         issues: derivation["issues"] || [],
         timeline: timeline_row(channel_row_label(channel), derivation)
       }}
    end
  end

  # Board C's channel row annotates overridden machinery inline; these fields
  # hold the override value itself ({:array, :map} / :map), not a boolean.
  def overridden_note(channel) do
    [
      channel.versions_override not in [nil, []] && "versions overridden",
      channel.entry_override not in [nil, %{}] && "entry overridden"
    ]
    |> Enum.filter(& &1)
    |> Enum.join(", ")
  end

  # The purl without its qualifier tail — some channels carry long
  # repository_url/vcs_url qualifiers that would drown the UI, so rendered
  # surfaces show the clean base purl only; the full string lives in the
  # rendering element's title attribute. A service has no purl, so it shows
  # the domain it answers on.
  def channel_label(package, channel) do
    case Channel.purl_string(package, channel) do
      nil -> channel.domain || channel.name
      purl -> purl |> String.split("?", parts: 2) |> hd()
    end
  end

  # The timeline's row label: the short channel name ("inets", "bandit"),
  # never the purl — purls belong on the chips.
  def channel_row_label(%{kind: :service} = channel), do: channel.domain || "service"
  def channel_row_label(channel), do: channel.name || channel.purl_type

  defp channel_derivation(nil, _key), do: nil
  defp channel_derivation(cache, channel_id), do: get_in(cache, ["channels", channel_id])

  # Board C's boundary timeline, from the same derivation_cache the derived
  # labels read. Every channel row is built the SAME way: its `versions` list
  # is a sequence of half-open [from, until) ranges, flattened literally onto
  # the track as intro/fixed node pairs with tinted vulnerable spans between
  # them and safe gaps elsewhere. A `versionType: "git"` entry is a commit-SHA
  # chain (a tree, not a line) and does not fit this linear track, so it is the
  # one entry type skipped everywhere — which leaves the repository channel
  # without a row unless it also carries version-shaped ranges.
  def timeline_rows(%{derivation_cache: nil}), do: []

  def timeline_rows(package) do
    cache = package.derivation_cache

    package.channels
    |> Enum.map(fn channel ->
      timeline_row(channel_row_label(channel), cache["channels"][channel.id])
    end)
    |> Enum.reject(&is_nil/1)
  end

  # A row's ranges become an ordered node sequence: each range contributes an
  # intro node, plus a fixed node unless it's open (`lessThan: "*"`, which
  # instead tints to the track's open end). A trailing pending fix (declared,
  # unreleased) appends a hollow node at the very end. Nodes are evenly spread
  # from 6% to 94% — version numbers have no common linear scale to place them
  # on honestly. A row with nothing to render (only git-SHA entries, or no
  # derivation at all) produces no row.
  defp timeline_row(_label, nil), do: nil

  defp timeline_row(label, derivation) do
    ranges =
      derivation["versions"]
      |> List.wrap()
      |> Enum.filter(&(&1["versionType"] in @renderable_version_types))

    pending? = (derivation["pending"] || []) != []

    # Each range is a {start_edge, stop_edge} pair. `"0"` (since the beginning)
    # and `"*"` (never fixed) are OPEN edges — no dot, the vulnerable tint just
    # runs off that side of the track. Everything else is a placed node.
    edges =
      Enum.map(ranges, fn range ->
        {edge(:intro, range["version"]), edge(:fix, range["lessThan"])}
      end)

    pending = if pending?, do: [{:pending, "fix unreleased"}], else: []

    if edges == [] and pending == [] do
      nil
    else
      {nodes, spans} = layout(edges, pending)
      %{label: label, nodes: nodes, spans: spans}
    end
  end

  # A range boundary is a placed node {kind, label} or an open edge :start / :end.
  defp edge(:intro, "0"), do: :start
  defp edge(:intro, version), do: {:intro, shorten(version)}
  defp edge(:fix, "*"), do: :end
  defp edge(:fix, upper), do: {:fix, shorten(upper)}

  # Lay every edge onto one ordered list of boundary points, coalescing a fix
  # that lands on the same version as the next range's intro into a SINGLE node
  # (a fix-and-reintroduce boundary — e.g. the `R13B03` where the unknown span
  # meets the affected one). Placed nodes are evenly spaced across 6%–94%; open
  # edges (`0` start / `*` end) hold no slot, tinting off the track edge. Nodes
  # and spans index the same list, so tints always meet their nodes.
  defp layout(edges, pending) do
    flat = Enum.flat_map(edges, fn {a, b} -> [a, b] end)
    points = coalesce(flat) ++ pending

    placed = Enum.filter(points, &match?({_kind, _tag}, &1))
    count = length(placed)

    positions =
      placed
      |> Enum.with_index()
      |> Map.new(fn {node, i} -> {node, node_pos(i, count)} end)

    nodes =
      Enum.map(placed, fn {kind, tag} = node -> %{kind: kind, tag: tag, pos: positions[node]} end)

    {nodes, spans(edges, positions)}
  end

  # Drop a `{:fix, v}` that is immediately followed by `{:intro, v}` for the same
  # version — they are one point on the timeline (the affected span simply
  # continues through it). Keeps the intro so the coalesced node reads as a start.
  defp coalesce([{:fix, v}, {:intro, v} | rest]), do: coalesce([{:intro, v} | rest])
  defp coalesce([point | rest]), do: [point | coalesce(rest)]
  defp coalesce([]), do: []

  defp node_pos(_index, 1), do: 6
  defp node_pos(index, count), do: 6 + round(index / (count - 1) * 88)

  # One tinted span per range: start edge → stop edge. Positions are looked up by
  # version label, so a fix edge that was coalesced into the next intro (same
  # version) still resolves to that shared node's percent.
  defp spans(edges, positions) do
    by_label = Map.new(positions, fn {{_kind, tag}, pos} -> {tag, pos} end)

    Enum.map(edges, fn {start_edge, stop_edge} ->
      %{start: edge_pos(start_edge, by_label), stop: edge_pos(stop_edge, by_label)}
    end)
  end

  defp edge_pos(:start, _by_label), do: 0
  defp edge_pos(:end, _by_label), do: 100
  defp edge_pos({_kind, tag}, by_label), do: Map.fetch!(by_label, tag)

  def derivation_issues(%{derivation_cache: nil}), do: []

  def derivation_issues(%{derivation_cache: cache}) do
    channel_issues =
      cache
      |> Map.get("channels", %{})
      |> Map.values()
      |> Enum.flat_map(&(&1["issues"] || []))

    Enum.uniq((cache["issues"] || []) ++ channel_issues)
  end

  def boundary_label(%{commit_sha: sha}) when is_binary(sha), do: shorten(sha)
  def boundary_label(%{version: version}), do: version

  # Full commit SHAs drown the tables; 12 characters identify them fine.
  def shorten(value) when is_binary(value) do
    if String.match?(value, ~r/^[0-9a-f]{40}$/) do
      String.slice(value, 0, 12) <> "…"
    else
      value
    end
  end

  def shorten(value), do: value
end
