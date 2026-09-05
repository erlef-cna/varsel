# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Description.AffectedSummaryTest do
  use ExUnit.Case, async: true

  alias Varsel.Cases.Description.AffectedSummary, as: Summary

  defp entry(name, purl, versions) do
    %{"packageName" => name, "packageURL" => purl, "versions" => versions}
  end

  # The renderer binds an OTP release's `OTP ` prefix to its version with
  # U+00A0; spelling that out in every assertion would hide what is tested. The
  # bare "OTP" naming the product is a word, not a prefix, so it keeps its space.
  defp nbsp(text), do: String.replace(text, ~r/OTP (?=[\dR])/, "OTP" <> <<0xC2, 0xA0>>)

  defp version(lower, upper, status \\ "affected", type \\ "semver") do
    %{"version" => lower, "lessThan" => upper, "status" => status, "versionType" => type}
  end

  describe "a single package" do
    test "one range" do
      affected = [entry("plug", "pkg:hex/plug", [version("0.1.0", "1.16.6")])]

      assert Summary.summarize(affected) ==
               "This issue affects plug: from 0.1.0 before 1.16.6."
    end

    test "two ranges join with 'and'" do
      affected = [
        entry("plug", "pkg:hex/plug", [version("0.1.0", "1.16.6"), version("1.17.0", "1.17.4")])
      ]

      assert Summary.summarize(affected) ==
               "This issue affects plug: from 0.1.0 before 1.16.6 and from 1.17.0 before 1.17.4."
    end

    # The serial comma keeps a three-item list from reading as two.
    test "three ranges take a serial comma" do
      affected = [
        entry("plug", "pkg:hex/plug", [
          version("0.1.0", "1.16.6"),
          version("1.17.0", "1.17.4"),
          version("1.18.0", "1.18.5")
        ])
      ]

      assert Summary.summarize(affected) ==
               "This issue affects plug: from 0.1.0 before 1.16.6, from 1.17.0 before 1.17.4, " <>
                 "and from 1.18.0 before 1.18.5."
    end
  end

  describe "open bounds" do
    test "the 0 sentinel is said by omission" do
      affected = [entry("bandit", "pkg:hex/bandit", [version("0", "1.11.0")])]

      assert Summary.summarize(affected) == "This issue affects bandit: before 1.11.0."
    end

    test "an unfixed range reads 'onward'" do
      affected = [entry("earmark", "pkg:hex/earmark", [version("1.4.1", "*")])]

      assert Summary.summarize(affected) == "This issue affects earmark: from 1.4.1 onward."
    end

    # An open range carrying `changes[]` is fixed, not unfixed: the transitions
    # are its fix boundaries, one per release line.
    test "an open range's fix transitions are named, not read as 'onward'" do
      versions = [
        %{
          "version" => "27.0",
          "lessThan" => "*",
          "status" => "affected",
          "versionType" => "otp",
          "changes" => [
            %{"at" => "27.3.4.15", "status" => "unaffected"},
            %{"at" => "28.5.0.4", "status" => "unaffected"},
            %{"at" => "29.0.4", "status" => "unaffected"}
          ]
        }
      ]

      affected = [entry("otp", "pkg:github/erlang/otp", versions)]

      assert Summary.summarize(affected) ==
               "This issue affects otp: from 27.0 before 27.3.4.15, 28.5.0.4, and 29.0.4."
    end

    test "a re-introducing transition is not a fix boundary" do
      versions = [
        %{
          "version" => "1.0.0",
          "lessThan" => "*",
          "status" => "affected",
          "versionType" => "semver",
          "changes" => [
            %{"at" => "1.5.0", "status" => "unaffected"},
            %{"at" => "2.0.0", "status" => "affected"}
          ]
        }
      ]

      affected = [entry("plug", "pkg:hex/plug", versions)]

      assert Summary.summarize(affected) == "This issue affects plug: from 1.0.0 before 1.5.0."
    end

    # An `affected` default lists what is safe, so the sentence is its
    # complement.
    test "an affected default reads as everything below the fixes" do
      unaffected = fn version ->
        %{
          "version" => version,
          "lessThan" => "*",
          "status" => "unaffected",
          "versionType" => "semver"
        }
      end

      one = [
        Map.put(
          entry("plug", "pkg:hex/plug", [unaffected.("1.5.3")]),
          "defaultStatus",
          "affected"
        )
      ]

      assert Summary.summarize(one) == "This issue affects plug: before 1.5.3."

      several =
        [
          Map.put(
            entry("plug", "pkg:hex/plug", [unaffected.("1.2.0"), unaffected.("3.0.0")]),
            "defaultStatus",
            "affected"
          )
        ]

      assert Summary.summarize(several) == "This issue affects plug: before 1.2.0 and 3.0.0."
    end

    test "an affected default with no fix reads as every version" do
      affected = [Map.put(entry("plug", "pkg:hex/plug", []), "defaultStatus", "affected")]

      assert Summary.summarize(affected) == "This issue affects plug: all versions."
    end

    test "lessThanOrEqual bounds the range like lessThan" do
      affected = [
        entry("thing", "pkg:hex/thing", [
          %{
            "version" => "1.0.0",
            "lessThanOrEqual" => "2.0.0",
            "status" => "affected",
            "versionType" => "semver"
          }
        ])
      ]

      assert Summary.summarize(affected) == "This issue affects thing: from 1.0.0 before 2.0.0."
    end
  end

  describe "several packages" do
    test "each takes its own clause, separated by semicolons" do
      affected = [
        entry("hex_core", "pkg:hex/hex_core", [version("0.1.0", "0.12.1")]),
        entry("hex", "pkg:hex/hex", [version("2.3.0", "2.3.2")]),
        entry("rebar3", "pkg:hex/rebar3", [version("3.9.1", "3.27.0")])
      ]

      assert Summary.summarize(affected) ==
               "This issue affects hex_core: from 0.1.0 before 0.12.1; hex: from 2.3.0 before 2.3.2; " <>
                 "rebar3: from 3.9.1 before 3.27.0."
    end
  end

  describe "Erlang/OTP names the release and the application together" do
    defp otp do
      [
        %{
          "packageName" => "otp",
          "packageURL" => "pkg:sid/erlang.org/otp",
          "versions" => [
            %{
              "version" => "17.0",
              "lessThan" => "28.0.3",
              "status" => "affected",
              "versionType" => "otp"
            }
          ]
        },
        %{
          "packageName" => "ssh",
          "packageURL" => "pkg:otp/ssh",
          "versions" => [
            %{
              "version" => "3.0.1",
              "lessThan" => "5.3.3",
              "status" => "affected",
              "versionType" => "otp"
            }
          ]
        }
      ]
    end

    # A reader knows one vocabulary or the other, so both are named — and the
    # `OTP ` prefix is what tells them which is which.
    test "the release carries an OTP prefix, the application does not" do
      assert Summary.summarize(otp()) ==
               nbsp(
                 "This issue affects OTP from OTP 17.0 before OTP 28.0.3, corresponding to " <>
                   "ssh from 3.0.1 before 5.3.3."
               )
    end

    # "OTP 29.0.2" is one token to a reader, so the prefix's own space binds to
    # its version — a line break between them would split the release name.
    test "the OTP prefix binds to its version" do
      otp = [
        %{
          "packageName" => "otp",
          "packageURL" => "pkg:sid/erlang.org/otp",
          "versions" => [
            %{
              "version" => "29.0.2",
              "lessThan" => "29.0.4",
              "status" => "affected",
              "versionType" => "otp"
            }
          ]
        }
      ]

      text = Summary.summarize(otp)

      assert text == nbsp("This issue affects OTP from OTP 29.0.2 before OTP 29.0.4.")
      refute String.contains?(text, "OTP 29.0.2")
    end

    test "R-series releases keep the prefix too" do
      otp = [
        %{
          "packageName" => "otp",
          "packageURL" => "pkg:sid/erlang.org/otp",
          "versions" => [
            %{
              "version" => "R13B03",
              "lessThan" => "27.3.4.15",
              "status" => "affected",
              "versionType" => "otp"
            }
          ]
        }
      ]

      assert Summary.summarize(otp) ==
               nbsp("This issue affects OTP from OTP R13B03 before OTP 27.3.4.15.")
    end

    test "several applications join with 'and'" do
      affected =
        otp() ++
          [
            %{
              "packageName" => "ssl",
              "packageURL" => "pkg:otp/ssl",
              "versions" => [
                %{
                  "version" => "11.2",
                  "lessThan" => "11.5.4",
                  "status" => "affected",
                  "versionType" => "otp"
                }
              ]
            }
          ]

      assert Summary.summarize(affected) =~
               "corresponding to ssh from 3.0.1 before 5.3.3, and ssl from 11.2 before 11.5.4."
    end
  end

  describe "what the sentence leaves out" do
    # "This issue affects" is a claim of certainty; an unknown row is the record
    # saying it has none.
    test "unknown rows get their own sentence, never the affects one" do
      affected = [
        entry("plug", "pkg:hex/plug", [
          version("0", "1.2.0", "unknown"),
          version("1.2.0", "1.16.6")
        ])
      ]

      assert Summary.summarize(affected) ==
               "This issue affects plug: from 1.2.0 before 1.16.6. " <>
                 "Whether plug before 1.2.0 is affected is unknown."
    end

    test "the unknown sentence keeps the OTP form, with its clause closed" do
      affected = [
        %{
          "packageName" => "otp",
          "packageURL" => "pkg:sid/erlang.org/otp",
          "versions" => [
            %{
              "version" => "0",
              "lessThan" => "R13B03",
              "status" => "unknown",
              "versionType" => "otp"
            },
            %{
              "version" => "R13B03",
              "lessThan" => "27.3.4.15",
              "status" => "affected",
              "versionType" => "otp"
            }
          ]
        },
        %{
          "packageName" => "ssh",
          "packageURL" => "pkg:otp/ssh",
          "versions" => [
            %{
              "version" => "0",
              "lessThan" => "1.1.7",
              "status" => "unknown",
              "versionType" => "otp"
            },
            %{
              "version" => "1.1.7",
              "lessThan" => "5.2.11.10",
              "status" => "affected",
              "versionType" => "otp"
            }
          ]
        }
      ]

      assert Summary.summarize(affected) =~
               nbsp(
                 "Whether OTP before OTP R13B03, corresponding to ssh before 1.1.7, " <>
                   "is affected is unknown."
               )
    end

    test "unaffected rows say nothing at all" do
      affected = [
        entry("plug", "pkg:hex/plug", [
          version("1.0.0", "2.0.0", "unaffected"),
          version("2.0.0", "2.5.0")
        ])
      ]

      assert Summary.summarize(affected) == "This issue affects plug: from 2.0.0 before 2.5.0."
    end

    # The commit range is the same fact in a vocabulary the sentence cannot read.
    test "a commit entry beside a version entry is dropped" do
      affected = [
        entry("plug", "pkg:hex/plug", [version("1.0.0", "2.0.0")]),
        entry("elixir-plug/plug", "pkg:github/elixir-plug/plug", [
          version(String.duplicate("a", 40), String.duplicate("b", 40), "affected", "git")
        ])
      ]

      assert Summary.summarize(affected) == "This issue affects plug: from 1.0.0 before 2.0.0."
    end

    # …but a product known ONLY by commit keeps them: that is all there is.
    test "a commit-only product still gets a sentence" do
      affected = [
        entry("hexpm", "pkg:github/hexpm/hexpm", [
          version("617e44c", "c692438", "affected", "git")
        ])
      ]

      assert Summary.summarize(affected) ==
               "This issue affects hexpm: from 617e44c before c692438."
    end

    # An image tag restates the release version once per flavor.
    test "an oci entry beside a version entry is dropped" do
      affected = [
        entry("gleam", "pkg:sid/gleam.run/gleam", [version("1.15.0", "1.18.0")]),
        entry("gleam-lang/gleam", "pkg:oci/gleam?repository_url=ghcr.io%2Fgleam-lang", [
          version("v1.15.0", "v1.18.0", "affected", "other"),
          version("v1.15.0-erlang", "v1.18.0-erlang", "affected", "other"),
          version("v1.15.0-scratch", "v1.18.0-scratch", "affected", "other")
        ])
      ]

      assert Summary.summarize(affected) == "This issue affects gleam: from 1.15.0 before 1.18.0."
    end

    # …but an image-only product keeps them: that is all there is.
    test "an oci-only product still gets a sentence" do
      affected = [
        entry("gleam-lang/gleam", "pkg:oci/gleam?repository_url=ghcr.io%2Fgleam-lang", [
          version("v1.15.0", "v1.18.0", "affected", "other")
        ])
      ]

      assert Summary.summarize(affected) ==
               "This issue affects gleam-lang/gleam: from v1.15.0 before v1.18.0."
    end

    test "nothing to say yields nil" do
      assert Summary.summarize([]) == nil
      assert Summary.summarize([entry("plug", "pkg:hex/plug", [])]) == nil
    end
  end

  describe "versions containing whitespace never wrap mid-version" do
    # Only U+00A0 is emitted; `Varsel.Cases.Markdown` turns it into `&nbsp;` for
    # the HTML representation, so there is nothing to encode twice.
    test "whitespace inside a version is bound" do
      spaced = [entry("thing", "pkg:hex/thing", [version("1.0 beta", "2.0 final")])]

      assert Summary.summarize(spaced) ==
               "This issue affects thing: from 1.0\u00A0beta before 2.0\u00A0final."
    end
  end

  describe "naming the product" do
    test "falls back to product, then vendor, when no package name exists" do
      product = [%{"product" => "Gleam", "versions" => [version("1.16.0", "1.17.0")]}]
      vendor = [%{"vendor" => "Acme", "versions" => [version("1.0.0", "2.0.0")]}]

      assert Summary.summarize(product) == "This issue affects Gleam: from 1.16.0 before 1.17.0."
      assert Summary.summarize(vendor) == "This issue affects Acme: from 1.0.0 before 2.0.0."
    end
  end
end
