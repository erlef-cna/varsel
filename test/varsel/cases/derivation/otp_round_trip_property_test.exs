# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Derivation.OtpRoundTripPropertyTest do
  @moduledoc """
  The round trip a published OTP record makes: a set of releases labelled
  affected or safe by git containment, derived into boundaries, emitted as
  `versions[]`, and resolved back per version.

  The property is that resolution returns what containment said. Anything else
  means the record misreports a real release — a false "not affected" being the
  worst answer the system can give.
  """
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Varsel.Cases.Derivation.Emit
  alias Varsel.Cases.PackageChannel
  alias Varsel.Cases.Reachability
  alias Varsel.Cases.Reachability.OTPVersion
  alias Varsel.CVE.VersionResolution

  @channel %PackageChannel{
    purl_type: "sid",
    namespace: "erlang.org",
    name: "otp",
    version_type: :otp,
    tag_suffixes: []
  }

  # A release line: a major, its minor releases, and the branch versions hanging
  # off them. Mirrors how OTP maintains several majors at once, which is the
  # shape that makes the timeline non-linear.
  defp line_versions(major) do
    gen all(
          minors <- list_of(integer(0..4), min_length: 1, max_length: 3),
          branch_depth <- frequency([{1, constant(0)}, {3, integer(1..3)}])
        ) do
      minors = minors |> Enum.uniq() |> Enum.sort()

      base = for minor <- minors, do: "#{major}.#{minor}"

      # Maintenance patches hang off the line's newest minor, which is how OTP
      # ships them and what makes two lines' fixes incomparable.
      branches =
        case minors do
          [] -> []
          _ -> for patch <- 1..branch_depth//1, do: "#{major}.#{List.last(minors)}.0.#{patch}"
        end

      base ++ branches
    end
  end

  defp release_sets do
    gen all(
          majors <- list_of(integer(17..40), min_length: 2, max_length: 4),
          majors = majors |> Enum.uniq() |> Enum.sort(),
          per_line <- fixed_list(Enum.map(majors, &line_versions/1))
        ) do
      List.flatten(per_line)
    end
  end

  # Containment: the vulnerability enters at one or more releases and is fixed
  # independently on each line it reaches. A release is affected when some
  # introducing boundary is at or below it and no fix covering it is.
  #
  # Several intros is the backported-bugfix shape: a change merged to two
  # maintenance branches introduces the flaw on each, and the releases between
  # a branch point and the backport are untouched.
  defp scenarios do
    gen all(
          versions <- release_sets(),
          versions = Enum.uniq(versions),
          # Weighted low and few: an intro near the start reaches several lines,
          # which is what produces a fix per line and exercises the partial
          # order. A uniform pick mostly lands late, leaving one line affected.
          intro_picks <-
            list_of(frequency([{1, constant(true)}, {6, constant(false)}]),
              length: length(versions)
            ),
          intro_index <-
            frequency([
              {4, constant(0)},
              {2, integer(0..max(div(length(versions), 3), 0))},
              {1, integer(0..max(length(versions) - 1, 0))}
            ]),
          # Weighted toward fixing: the interesting record is the one with
          # several fixes, not the one still open everywhere.
          fix_picks <-
            list_of(frequency([{3, constant(true)}, {2, constant(false)}]),
              length: length(versions)
            )
        ) do
      sorted = sort_versions(versions)

      intros =
        sorted
        |> Enum.zip(intro_picks)
        |> Enum.filter(&elem(&1, 1))
        |> Enum.map(&elem(&1, 0))
        |> then(&Enum.uniq([Enum.at(sorted, min(intro_index, length(sorted) - 1)) | &1]))

      # A fix on a line makes that release and everything after it ON THAT LINE
      # safe. Lines are independent, which is the whole point.
      fixes =
        sorted
        |> Enum.zip(fix_picks)
        |> Enum.filter(fn {version, picked?} -> picked? and introduced?(version, intros) end)
        |> Enum.map(&elem(&1, 0))

      affected =
        for version <- sorted,
            introduced?(version, intros),
            not fixed?(version, fixes),
            into: MapSet.new(),
            do: version

      %{versions: sorted, affected: affected}
    end
  end

  defp introduced?(version, intros) do
    Enum.any?(intros, fn intro -> at_or_after?(version, intro) end)
  end

  # The oracle's own comparison, written from the version scheme rather than
  # borrowed from the code under test.
  defp segments(version), do: version |> String.split(".") |> Enum.map(&String.to_integer/1)

  defp comparable?(a, b) do
    sa = segments(a)
    sb = segments(b)

    cond do
      length(sa) <= 3 and length(sb) <= 3 -> true
      length(sa) > 3 and length(sb) > 3 -> Enum.take(sa, 3) == Enum.take(sb, 3)
      length(sa) > 3 -> Enum.take(sb, 3) <= Enum.take(sa, 3)
      true -> Enum.take(sa, 3) <= Enum.take(sb, 3)
    end
  end

  defp at_or_after?(version, boundary) do
    comparable?(version, boundary) and segments(version) >= segments(boundary)
  end

  defp fixed?(version, fixes) do
    Enum.any?(fixes, fn fix -> at_or_after?(version, fix) end)
  end

  defp sort_versions(versions), do: Enum.sort_by(versions, &segments/1)

  # A round-trip property passes vacuously if the generator never builds the
  # shape it is meant to stress. These pin the corpus itself.
  test "the generator produces multi-line fixes that the version scheme does not order" do
    samples = Enum.take(scenarios(), 400)

    branchy =
      Enum.count(samples, fn %{versions: versions} ->
        Enum.any?(versions, &(length(String.split(&1, ".")) > 3))
      end)

    # A scenario where an unaffected release sits between two affected ones is
    # the backported-bugfix shape: the flaw entered separately on each line.
    gapped =
      Enum.count(samples, fn %{versions: versions, affected: affected} ->
        labels = Enum.map(versions, &MapSet.member?(affected, &1))
        first = Enum.find_index(labels, & &1)
        last = length(labels) - 1 - (labels |> Enum.reverse() |> Enum.find_index(& &1) || 0)
        first && Enum.any?(Enum.slice(labels, first..last), &(not &1))
      end)

    incomparable =
      Enum.count(samples, fn %{versions: versions, affected: affected} ->
        fixed =
          Reachability.deduce(versions, affected, comparator: :otp, include_prereleases: false).boundaries.fixed

        Enum.any?(for a <- fixed, b <- fixed, a != b, do: OTPVersion.compare(a, b) == :nc)
      end)

    assert branchy > 100, "only #{branchy}/400 scenarios carried branch versions"

    assert incomparable > 15,
           "only #{incomparable}/400 scenarios had fixes the scheme does not order — " <>
             "the property is not exercising the partial order"

    assert gapped > 5,
           "only #{gapped}/400 scenarios left an unaffected release between two affected ones — " <>
             "the property is not exercising a bugfix backported to several lines"
  end

  property "every release resolves to what containment said about it" do
    check all(%{versions: versions, affected: affected} <- scenarios(), max_runs: 2000) do
      {:ok, reach} =
        {:ok, Reachability.deduce(versions, affected, comparator: :otp, include_prereleases: false)}

      emitted =
        Emit.channel(@channel, reach.ranges, boundaries: reach.boundaries)["versions"]

      for version <- versions do
        expected = if MapSet.member?(affected, version), do: :affected, else: :unaffected

        assert VersionResolution.resolve(emitted, "unaffected", version) == {:ok, expected},
               """
               #{version} resolved wrongly.
                 expected:  #{expected}
                 got:       #{inspect(VersionResolution.resolve(emitted, "unaffected", version))}
                 versions:  #{inspect(versions)}
                 affected:  #{inspect(MapSet.to_list(affected))}
                 emitted:   #{inspect(emitted)}
               """
      end
    end
  end
end
