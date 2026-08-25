# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CVE.VersionResolutionTest do
  use ExUnit.Case, async: true

  alias Varsel.CVE.VersionResolution, as: VR

  defp resolve(versions, input, default \\ "unaffected") do
    VR.resolve(versions, default, input)
  end

  describe "single-version entries (no upper bound)" do
    @versions [%{"version" => "1.2.3", "status" => "affected", "versionType" => "semver"}]

    test "the named version takes the entry's status" do
      assert resolve(@versions, "1.2.3") == {:ok, :affected}
    end

    test "any other version falls through to defaultStatus" do
      assert resolve(@versions, "1.2.2") == {:ok, :unaffected}
      assert resolve(@versions, "1.2.4") == {:ok, :unaffected}
    end
  end

  describe "lessThan — upper bound is exclusive" do
    @versions [
      %{
        "version" => "1.5.0",
        "lessThan" => "1.5.8",
        "status" => "affected",
        "versionType" => "semver"
      }
    ]

    test "the lower bound is included" do
      assert resolve(@versions, "1.5.0") == {:ok, :affected}
    end

    test "inside the range is affected" do
      assert resolve(@versions, "1.5.4") == {:ok, :affected}
    end

    test "the upper bound itself is NOT in the range" do
      assert resolve(@versions, "1.5.8") == {:ok, :unaffected}
    end

    test "below the lower bound falls through" do
      assert resolve(@versions, "1.4.9") == {:ok, :unaffected}
    end
  end

  describe "lessThanOrEqual — upper bound is inclusive" do
    @versions [
      %{
        "version" => "1.5.0",
        "lessThanOrEqual" => "1.5.8",
        "status" => "affected",
        "versionType" => "semver"
      }
    ]

    test "the upper bound itself IS in the range" do
      assert resolve(@versions, "1.5.8") == {:ok, :affected}
    end

    test "just past the upper bound falls through" do
      assert resolve(@versions, "1.5.9") == {:ok, :unaffected}
    end
  end

  describe "defaultStatus — every value is honoured" do
    @versions [
      %{
        "version" => "1.0.0",
        "lessThan" => "2.0.0",
        "status" => "affected",
        "versionType" => "semver"
      }
    ]

    test "a version no entry covers takes the default" do
      assert resolve(@versions, "3.0.0", "unaffected") == {:ok, :unaffected}
      assert resolve(@versions, "3.0.0", "affected") == {:ok, :affected}
      assert resolve(@versions, "3.0.0", "unknown") == {:ok, :unknown}
    end

    test "an absent default is unknown, never assumed safe" do
      assert resolve(@versions, "3.0.0", nil) == {:ok, :unknown}
    end

    test "a covered version ignores the default entirely" do
      assert resolve(@versions, "1.5.0", "unaffected") == {:ok, :affected}
      assert resolve(@versions, "1.5.0", "affected") == {:ok, :affected}
    end
  end

  describe "per-entry status — any status on any row" do
    test "an unaffected range carves a hole in an affected-by-default product" do
      versions = [
        %{
          "version" => "1.2.0",
          "lessThan" => "1.3.0",
          "status" => "unaffected",
          "versionType" => "semver"
        }
      ]

      assert resolve(versions, "1.2.5", "affected") == {:ok, :unaffected}
      assert resolve(versions, "1.4.0", "affected") == {:ok, :affected}
    end

    test "an unknown range reports unknown, not a guess in either direction" do
      versions = [
        %{
          "version" => "0.1.0",
          "lessThan" => "1.0.0",
          "status" => "unknown",
          "versionType" => "semver"
        }
      ]

      assert resolve(versions, "0.5.0") == {:ok, :unknown}
    end
  end

  describe "first matching entry wins (the schema returns inside the loop)" do
    test "a later entry covering the same version is never consulted" do
      versions = [
        %{
          "version" => "1.0.0",
          "lessThan" => "2.0.0",
          "status" => "unaffected",
          "versionType" => "semver"
        },
        %{
          "version" => "1.0.0",
          "lessThan" => "2.0.0",
          "status" => "affected",
          "versionType" => "semver"
        }
      ]

      assert resolve(versions, "1.5.0") == {:ok, :unaffected}
    end
  end

  # TEMPORARY — drop the `@tag :skip`s below, and the describe above them, once
  # the published records stop using `changes[]` to mean "a fix per release
  # line".
  # These tests state the algorithm the spec defines and this module implements;
  # only the temporary gate in `comparable_entries/1` keeps them from passing.
  describe "changes[] resolution is temporarily disabled (bad legacy data)" do
    test "an entry carrying changes[] makes its product unaskable" do
      versions = [
        %{
          "version" => "26.0",
          "lessThan" => "*",
          "status" => "affected",
          "versionType" => "otp",
          "changes" => [
            %{"at" => "27.3.4", "status" => "unaffected"},
            %{"at" => "28.7.6", "status" => "unaffected"}
          ]
        }
      ]

      refute VR.resolvable?(versions)
      assert resolve(versions, "28.0.0") == {:error, :unsupported}
    end

    # Why it is disabled: applied per spec, 27.3.4 is the last transition at or
    # below 28.0.0, so 28.0.0 would answer "unaffected" — but OTP 28.0.0 is
    # affected until its own line's 28.7.6. Declining beats answering wrongly.
    test "the shape that would produce a false negative" do
      versions = [
        %{
          "version" => "26.0",
          "lessThan" => "*",
          "status" => "affected",
          "versionType" => "otp",
          "changes" => [%{"at" => "27.3.4", "status" => "unaffected"}]
        }
      ]

      refute match?({:ok, :unaffected}, resolve(versions, "28.0.0"))
    end
  end

  describe "changes[] — status transitions within a range" do
    @versions [
      %{
        "version" => "0.6.0",
        "lessThan" => "*",
        "status" => "affected",
        "versionType" => "semver",
        "changes" => [
          %{"at" => "1.7.22", "status" => "unaffected"},
          %{"at" => "1.8.0", "status" => "affected"},
          %{"at" => "1.8.6", "status" => "unaffected"}
        ]
      }
    ]

    @tag :skip
    test "before the first transition the entry's own status holds" do
      assert resolve(@versions, "1.0.0") == {:ok, :affected}
    end

    @tag :skip
    test "at and after a transition its status takes over" do
      assert resolve(@versions, "1.7.22") == {:ok, :unaffected}
      assert resolve(@versions, "1.7.99") == {:ok, :unaffected}
    end

    @tag :skip
    test "a later transition can move the version back to affected" do
      assert resolve(@versions, "1.8.0") == {:ok, :affected}
      assert resolve(@versions, "1.8.5") == {:ok, :affected}
    end

    @tag :skip
    test "the final transition wins above it" do
      assert resolve(@versions, "1.8.6") == {:ok, :unaffected}
      assert resolve(@versions, "99.0.0") == {:ok, :unaffected}
    end

    @tag :skip
    test "an unknown transition is reported as unknown" do
      versions = [
        %{
          "version" => "1.0.0",
          "lessThan" => "*",
          "status" => "affected",
          "versionType" => "semver",
          "changes" => [%{"at" => "2.0.0", "status" => "unknown"}]
        }
      ]

      assert resolve(versions, "2.5.0") == {:ok, :unknown}
    end

    # The schema applies changes in array order, not sorted order.
    @tag :skip
    test "changes apply in array order — a lower transition listed last still wins" do
      versions = [
        %{
          "version" => "1.0.0",
          "lessThan" => "*",
          "status" => "affected",
          "versionType" => "semver",
          "changes" => [
            %{"at" => "2.0.0", "status" => "unaffected"},
            %{"at" => "1.5.0", "status" => "affected"}
          ]
        }
      ]

      assert resolve(versions, "3.0.0") == {:ok, :affected}
    end

    @tag :skip
    test "a bounded range's changes still stop at its upper bound" do
      versions = [
        %{
          "version" => "1.0.0",
          "lessThan" => "2.0.0",
          "status" => "affected",
          "versionType" => "semver",
          "changes" => [%{"at" => "1.5.0", "status" => "unaffected"}]
        }
      ]

      assert resolve(versions, "1.4.0") == {:ok, :affected}
      assert resolve(versions, "1.6.0") == {:ok, :unaffected}
      # Outside the range entirely — the default answers, not the last change.
      assert resolve(versions, "2.5.0", "unknown") == {:ok, :unknown}
    end
  end

  describe "the zero sentinel sorts below every version" do
    # "By convention, typically 0 denotes the earliest possible version."
    test "a 0-bounded range covers everything below its upper bound" do
      versions = [
        %{
          "version" => "0",
          "lessThan" => "1.5.0",
          "status" => "affected",
          "versionType" => "semver"
        }
      ]

      assert resolve(versions, "0.0.1") == {:ok, :affected}
      assert resolve(versions, "1.4.9") == {:ok, :affected}
      assert resolve(versions, "1.5.0") == {:ok, :unaffected}
    end

    test "0 sorts below every OTP release" do
      versions = [
        %{"version" => "0", "lessThan" => "17.0", "status" => "unknown", "versionType" => "otp"}
      ]

      assert resolve(versions, "16.0") == {:ok, :unknown}
      assert resolve(versions, "17.0") == {:ok, :unaffected}
    end
  end

  describe "OTP versions" do
    # CVE-2026-900001's release channel, re-derived from 17.0: everything below
    # the first affected release is explicitly unknown, then affected up to
    # 27.3.4.15, with two later lines.
    @versions [
      %{"version" => "0", "lessThan" => "17.0", "status" => "unknown", "versionType" => "otp"},
      %{
        "version" => "17.0",
        "lessThan" => "27.3.4.15",
        "status" => "affected",
        "versionType" => "otp"
      },
      %{
        "version" => "28.0",
        "lessThan" => "28.5.0.4",
        "status" => "affected",
        "versionType" => "otp"
      },
      %{
        "version" => "29.0",
        "lessThan" => "29.0.4",
        "status" => "affected",
        "versionType" => "otp"
      }
    ]

    test "the sentinel answers unknown below the first affected release" do
      assert resolve(@versions, "16.0") == {:ok, :unknown}
      assert resolve(@versions, "17.0") == {:ok, :affected}
    end

    test "a release inside the first range is affected" do
      assert resolve(@versions, "19.2") == {:ok, :affected}
      assert resolve(@versions, "27.3.4.14") == {:ok, :affected}
    end

    test "each line's own fix boundary ends its range" do
      assert resolve(@versions, "27.3.4.15") == {:ok, :unaffected}
      assert resolve(@versions, "28.5.0.4") == {:ok, :unaffected}
      assert resolve(@versions, "29.0.4") == {:ok, :unaffected}
    end

    test "the gap between fixed lines is unaffected" do
      assert resolve(@versions, "28.0") == {:ok, :affected}
      assert resolve(@versions, "30.0") == {:ok, :unaffected}
    end

    test "an OTP- prefix is accepted on input" do
      assert resolve(@versions, "OTP-19.2") == {:ok, :affected}
    end

    # A record published before the R series was dropped. Its bound no longer
    # parses, and the all-or-nothing rule declines the whole product rather than
    # answering from the entries that do parse — which would understate the
    # affected span. These records are re-derived from 17.0 and republished.
    test "a legacy R-series bound makes the product unsupported" do
      versions = [
        %{
          "version" => "R13B03",
          "lessThan" => "27.3.4.15",
          "status" => "affected",
          "versionType" => "otp"
        }
      ]

      assert resolve(versions, "19.2") == {:error, :unsupported}
      refute VR.resolvable?(versions)
    end
  end

  describe "date versions (YYYY-MM-DD)" do
    # How a hosted service versions itself: there are no releases to name, only
    # the day the fix went out.
    @versions [
      %{
        "version" => "2024-01-01",
        "lessThan" => "2024-06-15",
        "status" => "affected",
        "versionType" => "date"
      }
    ]

    test "dates order as dates, not as strings" do
      assert resolve(@versions, "2023-12-31") == {:ok, :unaffected}
      assert resolve(@versions, "2024-01-01") == {:ok, :affected}
      assert resolve(@versions, "2024-03-05") == {:ok, :affected}
      assert resolve(@versions, "2024-06-14") == {:ok, :affected}
    end

    test "the upper bound is exclusive, same as any other scheme" do
      assert resolve(@versions, "2024-06-15") == {:ok, :unaffected}
    end

    @tag :skip
    test "changes[] transitions work on dates" do
      versions = [
        %{
          "version" => "2024-01-01",
          "lessThan" => "*",
          "status" => "affected",
          "versionType" => "date",
          "changes" => [%{"at" => "2024-06-15", "status" => "unaffected"}]
        }
      ]

      assert resolve(versions, "2024-05-01") == {:ok, :affected}
      assert resolve(versions, "2024-06-15") == {:ok, :unaffected}
      assert resolve(versions, "2030-01-01") == {:ok, :unaffected}
    end

    test "a non-date input is unparseable, never 'unaffected'" do
      assert resolve(@versions, "1.0.0") == {:error, :unparseable}
      assert resolve(@versions, "nonsense") == {:error, :unparseable}
      assert resolve(@versions, "2024-13-45") == {:error, :unparseable}
    end

    test "a date product is askable" do
      assert VR.resolvable?(@versions)
    end

    # hex.pm's entry in CVE-2026-90015: a hosted service affected since forever,
    # fixed on a date. The sentinel is about the bound, not the scheme.
    test "the 0 sentinel opens a date range too" do
      versions = [
        %{
          "version" => "0",
          "lessThan" => "2026-03-10",
          "status" => "affected",
          "versionType" => "date"
        }
      ]

      assert resolve(versions, "2020-01-01") == {:ok, :affected}
      assert resolve(versions, "2026-03-09") == {:ok, :affected}
      assert resolve(versions, "2026-03-10") == {:ok, :unaffected}
    end

    test "a malformed date boundary disqualifies the product" do
      refute VR.resolvable?([
               %{
                 "version" => "2024-01-01",
                 "lessThan" => "June 2024",
                 "status" => "affected",
                 "versionType" => "date"
               }
             ])
    end
  end

  describe "input parsing" do
    @versions [
      %{
        "version" => "1.5.0",
        "lessThan" => "1.6.0",
        "status" => "affected",
        "versionType" => "semver"
      }
    ]

    test "short semver input is zero-padded" do
      assert resolve(@versions, "1.5") == {:ok, :affected}
    end

    test "a leading v is accepted" do
      assert resolve(@versions, "v1.5.0") == {:ok, :affected}
    end

    test "surrounding whitespace is trimmed" do
      assert resolve(@versions, "  1.5.0  ") == {:ok, :affected}
    end

    test "prereleases order below their release" do
      assert resolve(@versions, "1.6.0-rc1") == {:ok, :affected}
    end

    test "garbage is unparseable, never 'unaffected'" do
      assert resolve(@versions, "latest") == {:error, :unparseable}
      assert resolve(@versions, "bandit-1.4") == {:error, :unparseable}
      assert resolve(@versions, "") == {:error, :unparseable}
    end
  end

  describe "ranges of an unorderable TYPE are skipped, not fatal" do
    # A git range beside the semver ones restates the same vulnerability by
    # commit. A typed semver version could never fall inside it, so skipping it
    # cannot change any answer — and refusing over it would silence the checker
    # on every record that pairs the two.
    test "a git range alongside orderable ranges is ignored" do
      versions = [
        %{
          "version" => "aaaaaaa",
          "lessThan" => "bbbbbbb",
          "status" => "affected",
          "versionType" => "git"
        },
        %{
          "version" => "1.0.0",
          "lessThan" => "2.0.0",
          "status" => "affected",
          "versionType" => "semver"
        }
      ]

      assert VR.resolvable?(versions)
      assert resolve(versions, "1.5.0") == {:ok, :affected}
      assert resolve(versions, "2.5.0") == {:ok, :unaffected}
    end

    test "a product of ONLY unorderable ranges cannot be asked" do
      versions = [
        %{
          "version" => "aaaaaaa",
          "lessThan" => "bbbbbbb",
          "status" => "affected",
          "versionType" => "git"
        }
      ]

      refute VR.resolvable?(versions)
    end
  end

  describe "all-or-nothing within a supported type" do
    # The false negative this rule exists to prevent: dropping the unparseable
    # entry would answer "unaffected" for everything it covers.
    test "one unparseable boundary disqualifies the whole product" do
      versions = [
        %{
          "version" => "1.0.0",
          "lessThan" => "not-a-version",
          "status" => "affected",
          "versionType" => "semver"
        },
        %{
          "version" => "2.0.0",
          "lessThan" => "2.5.0",
          "status" => "affected",
          "versionType" => "semver"
        }
      ]

      assert resolve(versions, "2.1.0") == {:error, :unsupported}
    end

    test "an unparseable changes[] boundary disqualifies it too" do
      versions = [
        %{
          "version" => "1.0.0",
          "lessThan" => "*",
          "status" => "affected",
          "versionType" => "semver",
          "changes" => [%{"at" => "garbage", "status" => "unaffected"}]
        }
      ]

      assert resolve(versions, "1.5.0") == {:error, :unsupported}
    end
  end

  describe "resolvable?/1 — can this product be asked at all" do
    test "true for orderable schemes" do
      assert VR.resolvable?([
               %{
                 "version" => "1.0.0",
                 "lessThan" => "2.0.0",
                 "status" => "affected",
                 "versionType" => "semver"
               }
             ])

      assert VR.resolvable?([
               %{
                 "version" => "17.0",
                 "lessThan" => "27.0",
                 "status" => "affected",
                 "versionType" => "otp"
               }
             ])
    end

    test "false for schemes with no ordering" do
      refute VR.resolvable?([
               %{
                 "version" => "aaaaaaa",
                 "lessThan" => "bbbbbbb",
                 "status" => "affected",
                 "versionType" => "git"
               }
             ])

      refute VR.resolvable?([
               %{
                 "version" => "1.0",
                 "lessThan" => "2.0",
                 "status" => "affected",
                 "versionType" => "custom"
               }
             ])
    end

    # A boundary that lies about its own scheme makes the product unaskable —
    # answering from the entries we *can* read would understate the span.
    test "false when a boundary won't parse under its declared scheme" do
      refute VR.resolvable?([
               %{
                 "version" => "1.0.0",
                 "lessThan" => "not-a-version",
                 "status" => "affected",
                 "versionType" => "semver"
               }
             ])
    end

    test "false with nothing to go on" do
      refute VR.resolvable?([])
    end
  end

  describe "no entries at all" do
    test "the default answers" do
      assert resolve([], "1.0.0", "affected") == {:ok, :affected}
      assert resolve([], "1.0.0", "unaffected") == {:ok, :unaffected}
      assert resolve([], "1.0.0", nil) == {:ok, :unknown}
    end
  end
end
