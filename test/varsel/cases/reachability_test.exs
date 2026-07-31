# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.ReachabilityTest do
  use ExUnit.Case, async: true

  alias Varsel.Cases.Reachability

  # deduce/3 takes the full tag universe + the affected-tag set. Tests declare a
  # timeline compactly as [{name, affected?}]; this splits it into the two args.
  defp deduce(timeline, opts) do
    all_tags = Enum.map(timeline, &elem(&1, 0))
    affected = for {name, true} <- timeline, into: MapSet.new(), do: name
    Reachability.deduce(all_tags, affected, opts)
  end

  defp versions(result), do: Enum.map(result.ranges, &{&1.from, &1.until})

  describe "single bounded range" do
    test "affected from the first version, fixed mid-line" do
      result =
        deduce(
          [{"1.0.0", true}, {"1.0.1", true}, {"1.0.2", false}, {"1.0.3", false}],
          comparator: :semver
        )

      assert versions(result) == [{"1.0.0", "1.0.2"}]
      assert result.call_outs == []
      assert result.open? == false
    end
  end

  describe "backport lines fixed separately stay distinct ranges" do
    test "a safe version between affected runs splits them (phoenix CVE-2026-32689 shape)" do
      result =
        deduce(
          [
            {"1.7.0", true},
            {"1.7.21", true},
            {"1.7.22", false},
            {"1.7.23", false},
            {"1.8.0", true},
            {"1.8.5", true},
            {"1.8.6", false}
          ],
          comparator: :semver
        )

      assert versions(result) == [
               {"1.7.0", "1.7.22"},
               {"1.8.0", "1.8.6"}
             ]
    end
  end

  describe "collapsing adjacent affected lines" do
    test "fully-affected consecutive lines merge into one range" do
      # 1.3.* and 1.4.* are entirely affected (no fix between); 1.5.0 fixes.
      result =
        deduce(
          [
            {"1.3.0", true},
            {"1.3.9", true},
            {"1.4.0", true},
            {"1.4.20", true},
            {"1.5.0", false}
          ],
          comparator: :semver
        )

      assert versions(result) == [{"1.3.0", "1.5.0"}]
    end
  end

  describe "OTP three-line backport (CVE-2025-48038 shape)" do
    test "a range per vulnerable major, none dropped" do
      result =
        deduce(
          [
            {"OTP-26.2.5.14", true},
            {"OTP-26.2.5.15", false},
            {"OTP-27.3.4.2", true},
            {"OTP-27.3.4.3", false},
            {"OTP-28.0.2", true},
            {"OTP-28.0.3", false},
            {"OTP-28.1", false}
          ],
          comparator: :otp,
          include_prereleases: false
        )

      assert versions(result) == [
               {"OTP-26.2.5.14", "OTP-26.2.5.15"},
               {"OTP-27.3.4.2", "OTP-27.3.4.3"},
               {"OTP-28.0.2", "OTP-28.0.3"}
             ]
    end
  end

  describe "OTP R-series + modern spanning vulnerability" do
    test "R releases sort below modern; each fixed separately is its own range" do
      result =
        deduce(
          [
            {"OTP_R16B02", true},
            {"OTP_R16B03", false},
            {"OTP-27.0", true},
            {"OTP-27.1", false}
          ],
          comparator: :otp,
          include_prereleases: false
        )

      assert versions(result) == [
               {"OTP_R16B02", "OTP_R16B03"},
               {"OTP-27.0", "OTP-27.1"}
             ]
    end
  end

  describe "mid-line intro (bandit 0.5 shape)" do
    test "the range starts where the intro actually lands, not at .0" do
      result =
        deduce(
          [
            {"0.5.0", false},
            {"0.5.8", false},
            {"0.5.9", true},
            {"0.5.10", true},
            {"0.5.11", false}
          ],
          comparator: :semver
        )

      assert versions(result) == [{"0.5.9", "0.5.11"}]
    end
  end

  describe "out-of-order backport / cherry-pick" do
    test "a fix then a re-introduction is simply two consecutive ranges" do
      result =
        deduce(
          [
            {"1.0.0", true},
            {"1.0.1", true},
            # the fix was cherry-picked to 1.0.2 out of order...
            {"1.0.2", false},
            # ...but 1.0.3 does NOT contain it (reverted / branched before)
            {"1.0.3", true},
            {"1.0.4", false}
          ],
          comparator: :semver
        )

      assert versions(result) == [
               {"1.0.0", "1.0.2"},
               {"1.0.3", "1.0.4"}
             ]

      assert result.call_outs == []
    end
  end

  describe "explicit versions (releases git never tagged)" do
    alias Varsel.Test.StubGitBackend

    @intro String.duplicate("a", 40)
    @fix String.duplicate("b", 40)

    # StubGitBackend keeps its state in a global :persistent_term, and all_tags/1
    # unions every stubbed commit of a repo — so each async test needs its own
    # repo URL or they clobber one another's universe.
    setup context do
      %{
        repo: "https://github.com/acme/#{context.test |> to_string() |> String.replace(~r/\W+/, "-")}"
      }
    end

    defp derive(repo, intros, fixes, explicit) do
      {:ok, result} =
        Reachability.derive(repo, intros, fixes,
          comparator: :semver,
          explicit_versions: explicit
        )

      result
    end

    # boruta_auth published 2.3.0/2.3.1 to Hex but tagged neither, so containment
    # can only see 2.3.2 and the derived range understates the affected span.
    test "an untagged intro version extends the range below the earliest tag", %{repo: repo} do
      StubGitBackend.stub_tags(%{
        {repo, @intro} => ["2.3.2", "2.3.4", "2.3.7"],
        {repo, @fix} => ["2.3.7"]
      })

      assert versions(derive(repo, [@intro], [@fix], [{:introduced, "2.3.0"}])) ==
               [{"2.3.0", "2.3.7"}]
    end

    test "without the explicit version the same facts start at the earliest tag", %{repo: repo} do
      StubGitBackend.stub_tags(%{
        {repo, @intro} => ["2.3.2", "2.3.4", "2.3.7"],
        {repo, @fix} => ["2.3.7"]
      })

      assert versions(derive(repo, [@intro], [@fix], [])) == [{"2.3.2", "2.3.7"}]
    end

    test "an untagged fix version closes an otherwise open range", %{repo: repo} do
      StubGitBackend.stub_tags(%{{repo, @intro} => ["1.0.0", "1.0.1", "1.0.2"]})

      assert versions(derive(repo, [@intro], [], [{:fixed, "1.0.2"}])) == [{"1.0.0", "1.0.2"}]
    end

    test "an untagged intro opens a second range after a fix", %{repo: repo} do
      StubGitBackend.stub_tags(%{
        {repo, @intro} => ["1.0.0"],
        {repo, @fix} => ["1.0.1", "2.0.0", "2.0.1"]
      })

      StubGitBackend.stub_all_tags(%{repo => ["1.0.0", "1.0.1", "2.0.0", "2.0.1"]})

      assert versions(derive(repo, [@intro], [@fix], [{:introduced, "2.0.1"}])) ==
               [{"1.0.0", "1.0.1"}, {"2.0.1", :unbounded}]
    end

    test "an explicit version overrides its own containment label", %{repo: repo} do
      StubGitBackend.stub_tags(%{
        {repo, @intro} => ["1.0.0", "1.0.1", "1.0.2"],
        {repo, @fix} => ["1.0.2"]
      })

      # 1.0.1 is contained-affected, but the human asserts the fix landed there.
      assert versions(derive(repo, [@intro], [@fix], [{:fixed, "1.0.1"}])) == [{"1.0.0", "1.0.1"}]
    end

    test "explicit versions alone bound a range without any commit facts", %{repo: repo} do
      StubGitBackend.stub_all_tags(%{repo => ["1.0.0", "1.1.0", "1.2.0", "1.3.0"]})

      explicit = [{:introduced, "1.1.0"}, {:fixed, "1.3.0"}]
      assert versions(derive(repo, [], [], explicit)) == [{"1.1.0", "1.3.0"}]
    end

    test "an unresolvable intro is not an issue when an explicit version supplies the boundary",
         %{repo: repo} do
      StubGitBackend.stub_tags(%{{repo, @intro} => []})
      StubGitBackend.stub_all_tags(%{repo => ["1.0.0", "1.1.0"]})

      assert derive(repo, [@intro], [], [{:introduced, "1.0.0"}]).issues == []
    end

    test "an unresolvable intro still reports an issue without one", %{repo: repo} do
      StubGitBackend.stub_tags(%{{repo, @intro} => []})
      StubGitBackend.stub_all_tags(%{repo => ["1.0.0"]})

      assert derive(repo, [@intro], [], []).issues == [
               "the introducing commit is contained in no release tag"
             ]
    end
  end

  describe "edge cases" do
    test "an affected span that is never fixed is open-ended" do
      result =
        deduce(
          [{"1.0.0", true}, {"1.0.1", false}, {"2.0.0", true}, {"2.0.1", true}],
          comparator: :semver
        )

      assert versions(result) == [
               {"1.0.0", "1.0.1"},
               {"2.0.0", :unbounded}
             ]

      assert result.open? == true
    end

    test "nothing affected yields no ranges" do
      result = deduce([{"1.0.0", false}, {"1.0.1", false}], comparator: :semver)
      assert result.ranges == []
    end

    test "non-release tags are ignored" do
      result =
        deduce(
          [{"nightly", false}, {"1.0.0", true}, {"v1.19-latest", false}, {"1.0.1", false}],
          comparator: :semver
        )

      assert versions(result) == [{"1.0.0", "1.0.1"}]
    end

    test "a prerelease and its release are distinct points bounding the range" do
      result =
        deduce(
          [{"1.0.0-rc1", true}, {"1.0.0", true}, {"1.0.1", false}],
          comparator: :semver,
          include_prereleases: true
        )

      assert versions(result) == [{"1.0.0-rc1", "1.0.1"}]
      assert result.call_outs == []
    end

    test "with include_prereleases: false a conflicting prerelease is called out, not dropped" do
      # The releases are all safe, but a prerelease is affected — surfaced.
      result =
        deduce(
          [{"1.0.0-rc1", true}, {"1.0.0", false}, {"1.0.1", false}],
          comparator: :otp,
          include_prereleases: false
        )

      assert result.ranges == []
      assert [call_out] = result.call_outs
      assert call_out.reason == :prerelease_conflict
      assert call_out.version == "1.0.0-rc1"
      assert call_out.dag_label == :affected
    end
  end
end
