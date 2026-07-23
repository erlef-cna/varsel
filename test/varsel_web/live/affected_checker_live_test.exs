# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.AffectedCheckerLiveTest do
  use VarselWeb.ConnCase, async: true

  import Phoenix.LiveViewTest

  alias VarselWeb.AffectedCheckerLive

  defp mount(conn, packages) do
    live_isolated(conn, AffectedCheckerLive, session: %{"packages" => packages})
  end

  describe "single checkable package" do
    @packages [
      %{
        "state" => "checkable",
        "purl" => "pkg:hex/bandit",
        "bare_name" => "bandit",
        "versions" => [
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
      }
    ]

    test "empty input shows the placeholder-toned line, no icon", %{conn: conn} do
      {:ok, view, html} = mount(conn, @packages)
      assert html =~ "type your bandit version to check"
      refute render(view) =~ "✗"
      refute render(view) =~ "✓"
    end

    test "renders no package selector for a single package", %{conn: conn} do
      {:ok, _view, html} = mount(conn, @packages)
      refute html =~ "pksel"
      refute html =~ "select-package"
    end

    test "typing an affected version shows the unsafe verdict naming the package, leading with its own branch's fix",
         %{conn: conn} do
      {:ok, view, _html} = mount(conn, @packages)

      html = view |> form("form", %{version: "1.4.9"}) |> render_change()

      assert html =~ "✗ bandit 1.4.9 is affected"
      assert html =~ "fixed in 1.4.11"
    end

    test "typing a fixed version on the latest branch shows the fixed verdict with no backport tail",
         %{conn: conn} do
      {:ok, view, _html} = mount(conn, @packages)

      html = view |> form("form", %{version: "1.5.8"}) |> render_change()

      assert html =~ "✓ bandit 1.5.8 includes the fix"
      refute html =~ "backported from"
    end

    test "typing the backport branch's own fix verbatim never says 'backported from itself'",
         %{conn: conn} do
      {:ok, view, _html} = mount(conn, @packages)

      html = view |> form("form", %{version: "1.4.11"}) |> render_change()

      assert html =~ "✓ bandit 1.4.11 includes the fix"
      assert html =~ "backported from 1.5.8"
      refute html =~ "backported from 1.4.11"
    end

    test "a single-range-style input strictly above the fix still resolves fixed (bare, since only one branch)",
         %{conn: conn} do
      {:ok, view, _html} = mount(conn, @packages)

      html = view |> form("form", %{version: "1.5.8"}) |> render_change()

      assert html =~ "✓ bandit 1.5.8 includes the fix"
    end

    test "typing a below-range version shows not-affected, distinct copy from fixed", %{
      conn: conn
    } do
      {:ok, view, _html} = mount(conn, @packages)

      html = view |> form("form", %{version: "0.5.2"}) |> render_change()

      assert html =~ "✓ bandit 0.5.2 is not affected"
      assert html =~ "the flaw was introduced in 0.6.0"
    end

    test "unparseable input never shows a colored verdict", %{conn: conn} do
      {:ok, view, _html} = mount(conn, @packages)

      html = view |> form("form", %{version: "bandit-1.4"}) |> render_change()

      assert html =~ "not a recognizable version"
      refute html =~ "text-error"
      refute html =~ "text-success"
    end

    test "clearing the input back to empty drops the verdict", %{conn: conn} do
      {:ok, view, _html} = mount(conn, @packages)

      view |> form("form", %{version: "1.4.9"}) |> render_change()
      html = view |> form("form", %{version: ""}) |> render_change()

      assert html =~ "type your bandit version to check"
    end

    test "the input is full-width below sm, capped at sm:w-56", %{conn: conn} do
      {:ok, _view, html} = mount(conn, @packages)
      assert html =~ "w-full"
      assert html =~ "sm:w-56"
    end
  end

  describe "multi-branch verdict grammar: user's own branch leads, others follow '; also fixed in'" do
    @packages [
      %{
        "state" => "checkable",
        "purl" => "pkg:hex/bandit",
        "bare_name" => "bandit",
        "versions" => [
          %{
            "version" => "1.5.0",
            "lessThan" => "1.5.8",
            "status" => "affected",
            "versionType" => "semver"
          },
          %{
            "version" => "0.6.0",
            "lessThan" => "1.4.11",
            "status" => "affected",
            "versionType" => "semver"
          }
        ]
      }
    ]

    test "affected on the 1.4 branch leads with its own fix, names the 1.5 branch as 'also fixed'",
         %{conn: conn} do
      {:ok, view, _html} = mount(conn, @packages)

      html = view |> form("form", %{version: "0.6.5"}) |> render_change()

      assert html =~ "✗ bandit 0.6.5 is affected"
      assert html =~ "fixed in 1.4.11 (1.4 series); also fixed in 1.5.8 (1.5 series)"
    end
  end

  describe "OTP-release package speaks OTP vocabulary" do
    @packages [
      %{
        "state" => "checkable",
        "purl" => "pkg:github/erlang/otp",
        "bare_name" => "ssh",
        "otp_release?" => true,
        "otp_package?" => true,
        "versions" => [
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
      }
    ]

    test "the placeholder reads 'OTP version, e.g. …'", %{conn: conn} do
      {:ok, _view, html} = mount(conn, @packages)
      assert html =~ "OTP version, e.g."
    end

    test "accepts the tag with or without the OTP- prefix, subject reads '<app> in OTP-<release>'",
         %{conn: conn} do
      {:ok, view, _html} = mount(conn, @packages)

      with_prefix = view |> form("form", %{version: "OTP-26.2.5.2"}) |> render_change()
      assert with_prefix =~ "✗ ssh in OTP-26.2.5.2 is affected"

      without_prefix = view |> form("form", %{version: "26.2.5.2"}) |> render_change()
      assert without_prefix =~ "✗ ssh in OTP-26.2.5.2 is affected"
    end

    test "names the user's own branch first, the sibling branch as 'also fixed in', every fix labeled",
         %{conn: conn} do
      {:ok, view, _html} = mount(conn, @packages)

      html = view |> form("form", %{version: "OTP-26.2.5.2"}) |> render_change()

      assert html =~ "fixed in OTP-26.2.5.6 (maint-26); also fixed in OTP-27.3.4 (maint-27)"
    end

    test "a version outside every known branch is not affected, never fixed by accident", %{
      conn: conn
    } do
      {:ok, view, _html} = mount(conn, @packages)

      html = view |> form("form", %{version: "OTP-28.0"}) |> render_change()

      assert html =~ "✓ ssh in OTP-28.0 is not affected"
    end
  end

  describe "OTP application-version fallback (no release mapping)" do
    @packages [
      %{
        "state" => "checkable",
        "purl" => "pkg:otp/ssh",
        "bare_name" => "ssh",
        "otp_release?" => false,
        "otp_package?" => true,
        "versions" => [
          %{
            "version" => "5.0.0",
            "lessThan" => "5.2.2",
            "status" => "affected",
            "versionType" => "semver"
          }
        ]
      }
    ]

    test "the placeholder reads '<app> application version, e.g. …'", %{conn: conn} do
      {:ok, _view, html} = mount(conn, @packages)
      assert html =~ "ssh application version, e.g."
    end

    test "the verdict subject reads '<app> <version> (OTP application)'", %{conn: conn} do
      {:ok, view, _html} = mount(conn, @packages)

      html = view |> form("form", %{version: "5.2.1"}) |> render_change()

      assert html =~ "✗ ssh 5.2.1 (OTP application) is affected"
      assert html =~ "fixed in 5.2.2"
    end
  end

  describe "placeholder example skips the zero-sentinel lower bound (CVE-2098-0003 shape)" do
    test "falls back to the first range with a real lower bound", %{conn: conn} do
      packages = [
        %{
          "state" => "checkable",
          "purl" => "pkg:hex/ash",
          "bare_name" => "ash",
          "versions" => [
            %{
              "version" => "0",
              "lessThan" => "3.5.39",
              "status" => "affected",
              "versionType" => "semver"
            },
            %{
              "version" => "4.0.0",
              "lessThan" => "4.2.0",
              "status" => "affected",
              "versionType" => "semver"
            }
          ]
        }
      ]

      {:ok, _view, html} = mount(conn, packages)
      assert html =~ "ash version, e.g. 4.0.0"
    end

    test "falls back to the generic 1.2.3 example when every range's lower bound is a sentinel",
         %{conn: conn} do
      packages = [
        %{
          "state" => "checkable",
          "purl" => "pkg:hex/ash",
          "bare_name" => "ash",
          "versions" => [
            %{
              "version" => "0",
              "lessThan" => "3.5.39",
              "status" => "affected",
              "versionType" => "semver"
            }
          ]
        }
      ]

      {:ok, _view, html} = mount(conn, packages)
      assert html =~ "ash version, e.g. 1.2.3"
    end
  end

  describe "checker presence: defaultStatus:affected with no versions[] renders a static verdict" do
    @packages [
      %{
        "state" => "all_affected",
        "purl" => "pkg:hex/release_tools",
        "bare_name" => "release_tools"
      }
    ]

    test "renders the red static verdict, no input", %{conn: conn} do
      {:ok, _view, html} = mount(conn, @packages)

      assert html =~ "✗ every version is affected"
      assert html =~ "no fixed release yet"
      refute html =~ "<input"
    end
  end

  describe "checker presence: git-only channel renders commit guidance, no input" do
    @packages [
      %{
        "state" => "git_only",
        "purl" => "pkg:github/umbrella/umbrella_native",
        "bare_name" => "umbrella_native",
        "intro_sha" => "aa11bb2",
        "fix_sha" => nil
      }
    ]

    test "renders the commit-tracking guidance line and the intro sha, no input", %{conn: conn} do
      {:ok, _view, html} = mount(conn, @packages)

      assert html =~ "tracks affected code by commit"
      assert html =~ "aa11bb2"
      refute html =~ "<input"
    end
  end

  describe "checker presence: non-orderable custom ranges render the honest unavailable line" do
    @packages [
      %{
        "state" => "unorderable",
        "purl" => "pkg:hex/provisioning-bridge",
        "bare_name" => "provisioning-bridge"
      }
    ]

    test "renders the honest line and an anchor to the Affected card, no input", %{conn: conn} do
      {:ok, _view, html} = mount(conn, @packages)

      assert html =~ "Version checking isn&#39;t available"
      assert html =~ "href=\"#affected\""
      refute html =~ "<input"
    end
  end

  describe "multi-package selector (pills, up to 4)" do
    @packages [
      %{
        "state" => "checkable",
        "purl" => "pkg:hex/cowlib",
        "bare_name" => "cowlib",
        "versions" => [
          %{
            "version" => "2.7.0",
            "lessThan" => "2.12.3",
            "status" => "affected",
            "versionType" => "semver"
          }
        ]
      },
      %{
        "state" => "checkable",
        "purl" => "pkg:hex/cowboy",
        "bare_name" => "cowboy",
        "versions" => [
          %{
            "version" => "2.8.0",
            "lessThan" => "2.13.1",
            "status" => "affected",
            "versionType" => "semver"
          }
        ]
      }
    ]

    test "defaults to the first affected package", %{conn: conn} do
      {:ok, _view, html} = mount(conn, @packages)
      assert html =~ "type your cowlib version to check"
    end

    test "renders a round pill per package", %{conn: conn} do
      {:ok, _view, html} = mount(conn, @packages)
      assert html =~ "pkg:hex/cowlib"
      assert html =~ "pkg:hex/cowboy"
      assert html =~ "rounded-full"
    end

    test "switching the pill swaps the placeholder, ranges and verdict but keeps the typed input",
         %{conn: conn} do
      {:ok, view, _html} = mount(conn, @packages)

      view |> form("form", %{version: "2.11.0"}) |> render_change()
      html = view |> element("button", "pkg:hex/cowboy") |> render_click()

      assert html =~ "value=\"2.11.0\""
      assert html =~ "✗ cowboy 2.11.0 is affected"
      refute html =~ "cowlib 2.11.0"
    end
  end

  describe "pills/select count ALL packages, including non-checkable states" do
    @packages [
      %{
        "state" => "checkable",
        "purl" => "pkg:hex/umbrella_core",
        "bare_name" => "umbrella_core",
        "versions" => [
          %{
            "version" => "0.1.0",
            "lessThan" => "2.1.0",
            "status" => "affected",
            "versionType" => "semver"
          }
        ]
      },
      %{
        "state" => "git_only",
        "purl" => "pkg:github/umbrella/umbrella_native",
        "bare_name" => "umbrella_native",
        "intro_sha" => "aa11bb2",
        "fix_sha" => nil
      }
    ]

    test "a git-only package still gets a pill alongside the checkable one", %{conn: conn} do
      {:ok, _view, html} = mount(conn, @packages)

      assert html =~ "pkg:hex/umbrella_core"
      assert html =~ "pkg:github/umbrella/umbrella_native"
    end

    test "selecting the git-only pill swaps the input for its guidance state", %{conn: conn} do
      {:ok, view, _html} = mount(conn, @packages)

      html = view |> element("button", "pkg:github/umbrella/umbrella_native") |> render_click()

      assert html =~ "tracks affected code by commit"
      refute html =~ "<input"
    end
  end

  describe "5+ packages renders a native select instead of pills" do
    @packages (for n <- 1..5 do
                 %{
                   "state" => "checkable",
                   "purl" => "pkg:hex/pkg#{n}",
                   "bare_name" => "pkg#{n}",
                   "versions" => [
                     %{
                       "version" => "1.0.0",
                       "lessThan" => "2.0.0",
                       "status" => "affected",
                       "versionType" => "semver"
                     }
                   ]
                 }
               end)

    test "renders a select, not round pills, for 5 or more packages", %{conn: conn} do
      {:ok, _view, html} = mount(conn, @packages)
      assert html =~ "<select"
      refute html =~ "rounded-full"
    end
  end

  describe "5+ packages including a non-checkable one still count toward the select threshold" do
    @packages (for n <- 1..4 do
                 %{
                   "state" => "checkable",
                   "purl" => "pkg:hex/pkg#{n}",
                   "bare_name" => "pkg#{n}",
                   "versions" => [
                     %{
                       "version" => "1.0.0",
                       "lessThan" => "2.0.0",
                       "status" => "affected",
                       "versionType" => "semver"
                     }
                   ]
                 }
               end) ++
                [
                  %{
                    "state" => "git_only",
                    "purl" => "pkg:github/umbrella/native5",
                    "bare_name" => "native5",
                    "intro_sha" => "aa11bb2",
                    "fix_sha" => nil
                  }
                ]

    test "4 checkable + 1 git-only = 5 packages renders a select", %{conn: conn} do
      {:ok, _view, html} = mount(conn, @packages)
      assert html =~ "<select"
      refute html =~ "rounded-full"
    end
  end
end
