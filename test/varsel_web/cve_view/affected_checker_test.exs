# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.CveView.AffectedCheckerTest do
  use ExUnit.Case, async: true

  alias VarselWeb.CveView
  alias VarselWeb.CveView.AffectedChecker, as: Checker

  describe "parse/2 — semver" do
    test "parses a plain major.minor.patch version" do
      assert %Version{major: 1, minor: 4, patch: 9} = Checker.parse("1.4.9", "semver")
    end

    test "zero-pads short major or major.minor versions" do
      assert Checker.parse("1.4", "semver") == Checker.parse("1.4.0", "semver")
      assert Checker.parse("2", "semver") == Checker.parse("2.0.0", "semver")
    end

    test "parses pre-release suffixes" do
      assert %Version{pre: ["rc1"]} = Checker.parse("1.4.9-rc1", "semver")
    end

    test "trims surrounding whitespace" do
      assert Checker.parse("  1.4.9  ", "semver") == Checker.parse("1.4.9", "semver")
    end

    test "rejects garbage input" do
      assert Checker.parse("", "semver") == :error
      assert Checker.parse("bandit-1.4", "semver") == :error
      assert Checker.parse("latest", "semver") == :error
      assert Checker.parse("1.4.x", "semver") == :error
    end
  end

  describe "parse/2 — otp" do
    test "parses dot-separated numeric segments" do
      assert Checker.parse("26.2.5.6", "otp") == {26, 2, 5, 6}
    end

    test "strips an OTP- prefix, with or without it present" do
      assert Checker.parse("OTP-26.2.5.6", "otp") == Checker.parse("26.2.5.6", "otp")
    end

    test "zero-pads missing trailing segments" do
      assert Checker.parse("26.2", "otp") == {26, 2, 0, 0}
      assert Checker.parse("26", "otp") == {26, 0, 0, 0}
    end

    test "rejects garbage input" do
      assert Checker.parse("", "otp") == :error
      assert Checker.parse("bandit-1.4", "otp") == :error
      assert Checker.parse("latest", "otp") == :error
      assert Checker.parse("OTP-26.x", "otp") == :error
    end
  end

  describe "parse/2 — unsupported versionType" do
    test "any type outside semver/otp is unparseable, never matched" do
      assert Checker.parse("2f81c44b1c2d3e4f5061728394a5b6c7d8e9f0a1", "git") == :error
      assert Checker.parse("2026-01-01", "date") == :error
    end
  end

  describe "compare/2" do
    test "compares two semver versions" do
      a = Checker.parse("1.4.9", "semver")
      b = Checker.parse("1.5.0", "semver")
      assert Checker.compare(a, b) == :lt
      assert Checker.compare(b, a) == :gt
      assert Checker.compare(a, a) == :eq
    end

    test "compares two OTP tuples" do
      a = Checker.parse("26.2.5.2", "otp")
      b = Checker.parse("26.2.5.6", "otp")
      assert Checker.compare(a, b) == :lt
      assert Checker.compare(b, a) == :gt
      assert Checker.compare(a, a) == :eq
    end
  end

  describe "supported_type?/1" do
    test "semver and otp are supported" do
      assert Checker.supported_type?("semver")
      assert Checker.supported_type?("otp")
    end

    test "everything else is unsupported" do
      refute Checker.supported_type?("git")
      refute Checker.supported_type?("date")
      refute Checker.supported_type?("custom")
      refute Checker.supported_type?(nil)
    end
  end

  describe "checkable?/1" do
    test "true when at least one affected range is semver or otp" do
      assert Checker.checkable?([%{"status" => "affected", "versionType" => "semver"}])
      assert Checker.checkable?([%{"status" => "affected", "versionType" => "otp"}])
    end

    test "false when every affected range is an unsupported type" do
      refute Checker.checkable?([%{"status" => "affected", "versionType" => "git"}])
      refute Checker.checkable?([%{"status" => "affected", "versionType" => "date"}])
    end

    test "false with no affected ranges at all" do
      refute Checker.checkable?([])
      refute Checker.checkable?([%{"status" => "unaffected", "versionType" => "semver"}])
    end
  end

  describe "match/2 — empty and unparseable" do
    @versions [
      %{
        "version" => "0.6.0",
        "lessThan" => "1.4.11",
        "status" => "affected",
        "versionType" => "semver"
      }
    ]

    test "empty input never verdicts" do
      assert Checker.match("", @versions) == {:empty}
      assert Checker.match(nil, @versions) == {:empty}
    end

    test "unparseable input never affected/fixed/not_affected — always :unparseable" do
      assert Checker.match("bandit-1.4", @versions) == {:unparseable}
      assert Checker.match("latest", @versions) == {:unparseable}
    end
  end

  describe "match/2 — single bounded semver range (a single fix)" do
    @versions [
      %{
        "version" => "1.5.0",
        "lessThan" => "1.5.8",
        "status" => "affected",
        "versionType" => "semver"
      }
    ]

    test "inside the range is affected, naming the fix, no other branches" do
      assert Checker.match("1.5.4", @versions) ==
               {:affected, %{raw: "1.5.8", branch_label: "1.5 series"}, []}
    end

    test "at the lower bound (inclusive) is affected" do
      assert Checker.match("1.5.0", @versions) ==
               {:affected, %{raw: "1.5.8", branch_label: "1.5 series"}, []}
    end

    test "exactly at the fix boundary is fixed, not affected — lessThan is exclusive" do
      assert Checker.match("1.5.8", @versions) ==
               {:fixed, %{raw: "1.5.8", branch_label: "1.5 series"}, %{raw: "1.5.8", branch_label: "1.5 series"}}
    end

    test "below the lower bound is not affected, naming the intro" do
      assert Checker.match("1.4.9", @versions) == {:not_affected, "1.5.0"}
    end

    test "well past the fix, same line, is fixed" do
      assert Checker.match("1.5.99", @versions) ==
               {:fixed, %{raw: "1.5.8", branch_label: "1.5 series"}, %{raw: "1.5.8", branch_label: "1.5 series"}}
    end

    test "a two-component input is zero-padded and compares fine" do
      assert Checker.match("1.5", @versions) ==
               {:affected, %{raw: "1.5.8", branch_label: "1.5 series"}, []}
    end

    test "a single-range package has no sibling branch: strictly ABOVE the fix (a different major/minor line entirely) still resolves to :fixed, never :not_affected" do
      # This is the sweep-confirmed bug: with only one range, there is no
      # "gap between branches" to protect against, so the same_line? guard
      # must not apply — a version numerically past the fix, on a wholly
      # different line, is still fixed because there's no other range that
      # could claim it instead.
      assert Checker.match("2.0.0", @versions) ==
               {:fixed, %{raw: "1.5.8", branch_label: "1.5 series"}, %{raw: "1.5.8", branch_label: "1.5 series"}}
    end
  end

  describe "match/2 — exact-fix-verbatim input never backports from itself" do
    @versions [
      %{
        "version" => "1.5.0",
        "lessThan" => "1.5.8",
        "status" => "affected",
        "versionType" => "semver"
      },
      %{
        "version" => "0.6.0",
        "lessThan" => "*",
        "status" => "affected",
        "versionType" => "semver",
        "changes" => [%{"at" => "1.4.11", "status" => "unaffected"}]
      }
    ]

    test "typing the latest branch's own fix verbatim names itself as the latest — no backport tail" do
      assert {:fixed, via, latest} = Checker.match("1.5.8", @versions)
      assert via == latest
      assert via.raw == "1.5.8"
    end

    test "typing the backport branch's fix verbatim: the tail names the LATEST branch's fix, not the typed version" do
      assert {:fixed, via, latest} = Checker.match("1.4.11", @versions)
      assert via.raw == "1.4.11"
      assert latest.raw == "1.5.8"
      refute via == latest
    end
  end

  describe "match/2 — lessThanOrEqual (inclusive upper bound)" do
    @versions [
      %{
        "version" => "1.0.0",
        "lessThanOrEqual" => "1.5.0",
        "status" => "affected",
        "versionType" => "semver"
      }
    ]

    test "at the boundary is still affected — lessThanOrEqual is inclusive" do
      assert Checker.match("1.5.0", @versions) ==
               {:affected, %{raw: "1.5.0", branch_label: "1.5 series"}, []}
    end

    test "just past the boundary is fixed" do
      assert {:fixed, via, _latest} = Checker.match("1.5.1", @versions)
      assert via.raw == "1.5.0"
    end
  end

  describe "match/2 — changes[] chain (single open range, chained fixes)" do
    @versions [
      %{
        "version" => "0.6.0",
        "lessThan" => "*",
        "status" => "affected",
        "versionType" => "semver",
        "changes" => [
          %{"at" => "1.4.9", "status" => "affected"},
          %{"at" => "1.4.11", "status" => "unaffected"}
        ]
      }
    ]

    test "before any change point is affected, naming the nearest fix" do
      assert Checker.match("1.0.0", @versions) ==
               {:affected, %{raw: "1.4.11", branch_label: "1.4 series"}, []}
    end

    test "an intermediate affected-status change point does not clear the verdict" do
      assert Checker.match("1.4.9", @versions) ==
               {:affected, %{raw: "1.4.11", branch_label: "1.4 series"}, []}
    end

    test "at the unaffected change point is fixed" do
      assert {:fixed, via, _latest} = Checker.match("1.4.11", @versions)
      assert via.raw == "1.4.11"
    end

    test "well past the fix, same minor line, stays fixed (open range has no upper guard)" do
      assert {:fixed, via, _latest} = Checker.match("1.4.99", @versions)
      assert via.raw == "1.4.11"
    end
  end

  describe "match/2 — changes[] chain with several unaffected boundaries, deliberately shuffled" do
    # CVE-2098-0002's ssh record shape verbatim: three chained fixes in one
    # open OTP range, arriving array-order 28.0.3, 27.3.4.3, 26.2.5.15 — the
    # range's OWN fix is the LOWEST one (26.2.5.15), not the last in the
    # array and not the largest.
    @otp_versions [
      %{
        "version" => "17.0",
        "lessThan" => "*",
        "status" => "affected",
        "versionType" => "otp",
        "changes" => [
          %{"at" => "28.0.3", "status" => "unaffected"},
          %{"at" => "27.3.4.3", "status" => "unaffected"},
          %{"at" => "26.2.5.15", "status" => "unaffected"}
        ]
      }
    ]

    test "an affected input names the lowest chained fix, never a later one" do
      assert Checker.match("OTP-26.2.5.2", @otp_versions) ==
               {:affected, %{raw: "26.2.5.15", branch_label: "maint-26"}, []}
    end

    test "single range: strictly past the lowest fix resolves to :fixed via that lowest fix" do
      assert {:fixed, via, latest} = Checker.match("OTP-27.3.4.3", @otp_versions)
      assert via.raw == "26.2.5.15"
      assert latest.raw == "26.2.5.15"
    end
  end

  describe "match/2 — multi-branch semver (independent release lines)" do
    @versions [
      %{
        "version" => "1.5.0",
        "lessThan" => "1.5.8",
        "status" => "affected",
        "versionType" => "semver"
      },
      %{
        "version" => "0.6.0",
        "lessThan" => "*",
        "status" => "affected",
        "versionType" => "semver",
        "changes" => [%{"at" => "1.4.11", "status" => "unaffected"}]
      }
    ]

    test "affected in the 1.4 line leads with that line's own fix, names the 1.5 line as 'also fixed'" do
      assert Checker.match("1.4.9", @versions) ==
               {:affected, %{raw: "1.4.11", branch_label: "1.4 series"}, [%{raw: "1.5.8", branch_label: "1.5 series"}]}
    end

    test "affected in the 1.5 line leads with that line's own fix, names the 1.4 line as 'also fixed'" do
      assert Checker.match("1.5.2", @versions) ==
               {:affected, %{raw: "1.5.8", branch_label: "1.5 series"}, [%{raw: "1.4.11", branch_label: "1.4 series"}]}
    end

    test "fixed in the 1.4 line" do
      assert {:fixed, via, _latest} = Checker.match("1.4.11", @versions)
      assert via.raw == "1.4.11"
    end

    test "fixed in the 1.5 line" do
      assert {:fixed, via, _latest} = Checker.match("1.5.8", @versions)
      assert via.raw == "1.5.8"
    end

    test "below every range is not affected, naming the earliest intro" do
      assert Checker.match("0.5.2", @versions) == {:not_affected, "0.6.0"}
    end
  end

  describe "match/2 — OTP-style orderable tags, not semver" do
    @versions [
      %{
        "version" => "OTP-27.0",
        "lessThan" => "OTP-27.3.4",
        "status" => "affected",
        "versionType" => "otp"
      },
      %{
        "version" => "OTP-26.0",
        "lessThan" => "OTP-26.2.5.6",
        "status" => "affected",
        "versionType" => "otp"
      }
    ]

    test "accepts the tag with the OTP- prefix" do
      assert Checker.match("OTP-26.2.5.2", @versions) ==
               {:affected, %{raw: "OTP-26.2.5.6", branch_label: "maint-26"},
                [%{raw: "OTP-27.3.4", branch_label: "maint-27"}]}
    end

    test "accepts the tag without the OTP- prefix, same verdict" do
      assert Checker.match("26.2.5.2", @versions) ==
               {:affected, %{raw: "OTP-26.2.5.6", branch_label: "maint-26"},
                [%{raw: "OTP-27.3.4", branch_label: "maint-27"}]}
    end

    test "names the branch's own fix first, the sibling branch's fix as 'also fixed'" do
      assert Checker.match("OTP-27.1.0", @versions) ==
               {:affected, %{raw: "OTP-27.3.4", branch_label: "maint-27"},
                [%{raw: "OTP-26.2.5.6", branch_label: "maint-26"}]}
    end

    test "fixed exactly at the maint-26 boundary" do
      assert {:fixed, via, _latest} = Checker.match("OTP-26.2.5.6", @versions)
      assert via.raw == "OTP-26.2.5.6"
    end

    test "a release line with no versions[] entry at all is not affected, never fixed by accident" do
      # OTP-28.0 numerically exceeds both known lines' fix boundaries, but it
      # belongs to neither — this is the "gap between branches" trap a naive
      # >= comparison would misreport as :fixed. TWO ranges exist here, so
      # the same_line? guard correctly still applies (unlike the
      # single-range case above).
      assert Checker.match("OTP-28.0", @versions) == {:not_affected, "OTP-26.0"}
    end

    test "below every known line is not affected" do
      assert Checker.match("OTP-25.3", @versions) == {:not_affected, "OTP-26.0"}
    end
  end

  describe "match/2 — unsupported-type ranges are excluded from matching" do
    @versions [
      %{
        "version" => "2f81c44b1c2d3e4f5061728394a5b6c7d8e9f0a1",
        "lessThan" => "d94a7c0b1c2d3e4f5061728394a5b6c7d8e9f0a1",
        "status" => "affected",
        "versionType" => "git"
      }
    ]

    test "no semver/otp ranges to match against yields not_affected with no intro" do
      assert Checker.match("1.0.0", @versions) == {:not_affected, nil}
    end
  end

  describe "match/2 — boundary exactness" do
    @versions [
      %{
        "version" => "1.0.0",
        "lessThan" => "2.0.0",
        "status" => "affected",
        "versionType" => "semver"
      }
    ]

    test "one patch below the fix is still affected" do
      assert Checker.match("1.9.9999", @versions) ==
               {:affected, %{raw: "2.0.0", branch_label: "2.0 series"}, []}
    end

    test "the fix version itself is fixed, never affected" do
      assert {:fixed, via, _latest} = Checker.match("2.0.0", @versions)
      assert via.raw == "2.0.0"
    end

    test "the lower bound itself is affected, never not_affected" do
      assert Checker.match("1.0.0", @versions) ==
               {:affected, %{raw: "2.0.0", branch_label: "2.0 series"}, []}
    end

    test "one component below the lower bound is not affected" do
      assert Checker.match("0.9.9999", @versions) == {:not_affected, "1.0.0"}
    end
  end

  describe "match/2 — CVE-2098-0002 regression (ssh, real multi-representation record)" do
    # After R1 (purl-strip) + R2 (dedup) normalization, only ONE orderable
    # representation of this range reaches the matcher: the otp-typed
    # range (17.0, fixed via three chained release points on the SAME
    # entry: 26.2.5.15, 27.3.4.3, 28.0.3). The purl-typed duplicate and the
    # git-typed range are excluded (purl dedupes away, git is a distinct
    # family and unsupported by this matcher).
    @otp_versions [
      %{
        "version" => "17.0",
        "lessThan" => "*",
        "status" => "affected",
        "versionType" => "otp",
        "changes" => [
          %{"at" => "28.0.3", "status" => "unaffected"},
          %{"at" => "27.3.4.3", "status" => "unaffected"},
          %{"at" => "26.2.5.15", "status" => "unaffected"}
        ]
      }
    ]

    test "a version above every known fix boundary resolves via the single-range rule — :fixed, naming the lowest chained fix" do
      # 30.0 exceeds every chained fix point; this is the package's ONLY
      # orderable range (git/purl duplicates never reach the matcher), so
      # per the single-range rule this must be :fixed, not :not_affected —
      # there is no sibling branch this could have fallen into a gap of.
      # "Fixed in" names the LOWEST chained fix (26.2.5.15) — the first safe
      # version of this line, per the user's ruling (not the array-order-last
      # 28.0.3 the seed data deliberately shuffles ahead of it).
      assert {:fixed, via, _latest} = Checker.match("30.0", @otp_versions)
      assert via.raw == "26.2.5.15"
    end

    test "a version below the lower bound is not affected" do
      assert Checker.match("16.3", @otp_versions) == {:not_affected, "17.0"}
    end

    test "a version mid-range is affected, naming the lowest chained fix" do
      assert Checker.match("20.0", @otp_versions) ==
               {:affected, %{raw: "26.2.5.15", branch_label: "maint-26"}, []}
    end
  end

  describe "CveView.normalize_versions/1 on CVE-2098-0002's ssh record (purl + otp + git representations)" do
    @ssh_versions [
      %{
        "version" => "pkg:otp/ssh@3.0.1",
        "lessThan" => "pkg:otp/ssh@*",
        "status" => "affected",
        "versionType" => "purl",
        "changes" => [
          %{"at" => "pkg:otp/ssh@5.3.3", "status" => "unaffected"},
          %{"at" => "pkg:otp/ssh@5.2.11.3", "status" => "unaffected"},
          %{"at" => "pkg:otp/ssh@5.1.4.12", "status" => "unaffected"}
        ]
      },
      %{
        "version" => "17.0",
        "lessThan" => "*",
        "status" => "affected",
        "versionType" => "otp",
        "changes" => [
          %{"at" => "28.0.3", "status" => "unaffected"},
          %{"at" => "27.3.4.3", "status" => "unaffected"},
          %{"at" => "26.2.5.15", "status" => "unaffected"}
        ]
      },
      %{
        "version" => "07b8f441ca711f9812fad9e9115bab3c3aa92f79",
        "lessThan" => "*",
        "status" => "affected",
        "versionType" => "git",
        "changes" => [
          %{"at" => "5f9af63eec4657a37663828d206517828cb9f288", "status" => "unaffected"}
        ]
      }
    ]

    test "purl and otp entries are distinct families (different version schemes), git stays separate too" do
      normalized = CveView.normalize_versions(@ssh_versions)
      checkable = Enum.filter(normalized, &Checker.supported_type?(&1["versionType"]))

      assert length(checkable) == 2
      assert Enum.any?(checkable, &(&1["versionType"] == "otp" and &1["version"] == "17.0"))
      assert Enum.any?(checkable, &(&1["versionType"] == "semver" and &1["version"] == "3.0.1"))

      # The git representation is a genuinely separate range family (different
      # shas, not a numeric duplicate) and is excluded from `checkable`.
      assert Enum.any?(normalized, &(&1["versionType"] == "git"))
    end

    test "30.0 against the otp-release-only ranges resolves via the single-range rule, never sourced from a purl/git duplicate" do
      # This mirrors what VarselWeb.CveHTML.checker_package/1 does: when both
      # an otp-release range and a semver app-version range exist, the
      # release ranges are what the checker actually matches against (rule
      # 3: never mix vocabularies in one checker). "Fixed in" names the
      # LOWEST chained fix, per the user's ruling.
      normalized = CveView.normalize_versions(@ssh_versions)
      otp_only = Enum.filter(normalized, &(&1["versionType"] == "otp"))

      assert {:fixed, via, _latest} = Checker.match("30.0", otp_only)
      assert via.raw == "26.2.5.15"
    end
  end

  describe "ranges without a changes key (real records, e.g. CVE-2026-20038)" do
    test "normalized nil changes do not crash matching and lessThan drives the verdict" do
      # The canonical shape produced by normalize_versions for a version
      # that only had lessThan — the "changes" key EXISTS with a list value
      # after normalization; this test locks that invariant end to end.
      [package] =
        VarselWeb.CveHTML.checker_packages([
          %{
            "vendor" => "mtrudel",
            "product" => "bandit",
            "packageURL" => "pkg:hex/bandit",
            "defaultStatus" => "unaffected",
            "versions" => [
              %{
                "version" => "0",
                "lessThan" => "1.11.0",
                "status" => "affected",
                "versionType" => "semver"
              }
            ]
          }
        ])

      assert package["state"] == "checkable"
      assert [%{"changes" => changes} | _rest] = package["versions"]
      assert is_list(changes)

      assert {:affected, %{raw: "1.11.0"}, _others} = Checker.match("1.0.0", package["versions"])
      assert :fixed = package["versions"] |> then(&Checker.match("1.11.0", &1)) |> elem(0)
    end
  end
end
