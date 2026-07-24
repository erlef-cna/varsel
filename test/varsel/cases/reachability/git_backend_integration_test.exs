# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Reachability.GitBackendIntegrationTest do
  @moduledoc """
  Exercises the full backend seam: `Reachability.derive/4` gathers containment
  from the (stubbed) `GitBackend` — `all_tags/1` for the universe, one
  `tags_containing/2` per commit — computes `affected = intros - fixes`, and
  runs the pure `deduce/3`. Same path production uses with `GitRepo`.
  """
  use ExUnit.Case, async: true

  alias Varsel.Cases.Reachability
  alias Varsel.Test.StubGitBackend

  @repo "https://github.com/acme/pkg"

  defp derive(intros, fixes, opts) do
    {:ok, result} = Reachability.derive(@repo, intros, fixes, opts)
    result
  end

  defp versions(result), do: Enum.map(result.ranges, &{&1.from, &1.until})

  test "semver backport lines through the stub" do
    StubGitBackend.stub_tags(%{
      {@repo, "intro"} => ["1.7.0", "1.7.21", "1.7.22", "1.7.23", "1.8.0", "1.8.5", "1.8.6"],
      {@repo, "fix17"} => ["1.7.22", "1.7.23", "1.8.6"],
      {@repo, "fix18"} => ["1.8.6"]
    })

    result = derive(["intro"], ["fix17", "fix18"], comparator: :semver)

    assert versions(result) == [
             {"1.7.0", "1.7.22"},
             {"1.8.0", "1.8.6"}
           ]

    assert result.call_outs == []
  end

  test "multiple intro commits union: affected if contained by ANY intro" do
    # introA covers the 1.x line, introB re-introduces on the 2.x line.
    StubGitBackend.stub_tags(%{
      {@repo, "introA"} => ["1.0.0", "1.0.1"],
      {@repo, "introB"} => ["2.0.0", "2.0.1"],
      {@repo, "fix"} => ["1.0.1", "2.0.1"]
    })

    StubGitBackend.stub_all_tags(%{@repo => ["1.0.0", "1.0.1", "2.0.0", "2.0.1"]})

    result = derive(["introA", "introB"], ["fix"], comparator: :semver)

    assert versions(result) == [
             {"1.0.0", "1.0.1"},
             {"2.0.0", "2.0.1"}
           ]
  end

  test "a fix contained in no tag is pending and leaves the range open" do
    StubGitBackend.stub_tags(%{
      {@repo, "intro"} => ["1.0.0", "1.0.1"],
      {@repo, "fix"} => []
    })

    result = derive(["intro"], ["fix"], comparator: :semver)

    assert versions(result) == [{"1.0.0", :unbounded}]
    assert result.pending_fixes == ["fix"]
    assert result.open? == true
  end

  test "an unresolvable intro reports an issue and no ranges" do
    StubGitBackend.stub_tags(%{{@repo, "fix"} => ["2.0.0"]})
    StubGitBackend.stub_all_tags(%{@repo => ["1.0.0", "2.0.0"]})

    result = derive(["intro"], ["fix"], comparator: :semver)

    assert result.ranges == []
    assert result.issues == ["the introducing commit is contained in no release tag"]
  end

  test "OTP release tags flow through and non-release tags drop out" do
    StubGitBackend.stub_tags(%{
      {@repo, "intro"} => ["OTP-27.0", "OTP-27.1", "latest", "OTP-28.0"],
      {@repo, "fix"} => ["OTP-27.1", "OTP-28.0"]
    })

    result = derive(["intro"], ["fix"], comparator: :otp, include_prereleases: false)

    # 27.0 affected up to 27.1; 28.0 already contains the fix (safe). Bounds carry
    # the raw tag names (prefix stripping is a later Emit concern).
    assert versions(result) == [{"OTP-27.0", "OTP-27.1"}]
    assert result.call_outs == []
  end
end
