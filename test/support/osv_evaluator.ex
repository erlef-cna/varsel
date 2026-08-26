# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Test.OsvEvaluator do
  @moduledoc """
  The OSV schema's `IsVulnerable` algorithm, transcribed from the pseudocode in
  https://ossf.github.io/osv-schema/#evaluation.

  A converted record is only correct if a consumer running this answers what the
  CVE record answers, so tests resolve a version both ways and compare. Written
  from the specification rather than from `Varsel.CVE.OsvConverter`, so the two
  cannot agree by sharing a mistake.

      func IncludedInRanges(v, ranges)
        for range in ranges
          if BeforeLimits(v, range)
            vulnerable = false
            for evt in sorted(range.events)
              if evt.introduced is present && v >= evt.introduced
                vulnerable = true
              else if evt.fixed is present && v >= evt.fixed
                vulnerable = false
              else if evt.last_affected is present && v > evt.last_affected
                vulnerable = false
            if vulnerable
              return true
        return false
  """

  alias Varsel.Cases.Reachability.VersionComparator

  @doc """
  Whether `version` is vulnerable per an OSV `affected[]` entry.

  `kind` names the scheme the range's versions are written in, so `"0"` and the
  ordering match what the consumer would use.
  """
  @spec vulnerable?(map(), String.t(), VersionComparator.kind()) :: boolean()
  def vulnerable?(affected, version, kind) do
    included_in_versions?(affected, version) or included_in_ranges?(affected, version, kind)
  end

  defp included_in_versions?(affected, version) do
    version in List.wrap(affected["versions"])
  end

  defp included_in_ranges?(affected, version, kind) do
    affected["ranges"]
    |> List.wrap()
    |> Enum.any?(&range_covers?(&1, version, kind))
  end

  defp range_covers?(range, version, kind) do
    events = List.wrap(range["events"])

    before_limits?(events, version, kind) and
      Enum.reduce(sorted(events, kind), false, fn event, vulnerable? ->
        cond do
          at_or_after?(version, event["introduced"], kind) -> true
          at_or_after?(version, event["fixed"], kind) -> false
          after?(version, event["last_affected"], kind) -> false
          true -> vulnerable?
        end
      end)
  end

  defp before_limits?(events, version, kind) do
    limits = for %{"limit" => limit} <- events, do: limit

    limits == [] or Enum.any?(limits, &before?(version, &1, kind))
  end

  # `introduced: "0"` sorts before every version, and `limit: "*"` stands for
  # infinity.
  defp at_or_after?(_version, nil, _kind), do: false
  defp at_or_after?(_version, "0", _kind), do: true
  defp at_or_after?(version, bound, kind), do: compare(version, bound, kind) != :lt

  defp after?(_version, nil, _kind), do: false
  defp after?(version, bound, kind), do: compare(version, bound, kind) == :gt

  defp before?(_version, "*", _kind), do: true
  defp before?(version, bound, kind), do: compare(version, bound, kind) == :lt

  defp sorted(events, kind) do
    Enum.sort_by(events, &event_version/1, fn a, b ->
      cond do
        a == nil -> true
        b == nil -> false
        a == "0" -> true
        b == "0" -> false
        true -> compare(a, b, kind) != :gt
      end
    end)
  end

  defp event_version(event) do
    Enum.find_value(~w(introduced fixed last_affected limit), &event[&1])
  end

  defp compare(a, b, kind), do: VersionComparator.compare(kind, a, b)
end
