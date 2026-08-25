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

  defp package(fields) do
    Map.merge(
      %{
        "purl" => "pkg:hex/bandit",
        "bare_name" => "bandit",
        "versions" => [],
        "default_status" => "unaffected",
        "askable?" => true,
        "otp_release?" => false,
        "otp_package?" => false
      },
      fields
    )
  end

  defp semver(version, less_than, status \\ "affected") do
    %{
      "version" => version,
      "lessThan" => less_than,
      "status" => status,
      "versionType" => "semver"
    }
  end

  describe "verdicts follow the record's own status" do
    defp bandit_packages, do: [package(%{"versions" => [semver("1.5.0", "1.5.8")]})]

    test "the empty box asks rather than answers", %{conn: conn} do
      {:ok, view, html} = mount(conn, bandit_packages())

      assert html =~ "type your bandit version to check"
      refute render(view) =~ "✗"
      refute render(view) =~ "✓"
    end

    test "a version inside an affected range is affected", %{conn: conn} do
      {:ok, view, _html} = mount(conn, bandit_packages())

      html = view |> form("form", %{version: "1.5.4"}) |> render_change()

      assert html =~ "✗ bandit 1.5.4 is affected"
      assert html =~ "text-error"
    end

    test "the exclusive upper bound is not affected", %{conn: conn} do
      {:ok, view, _html} = mount(conn, bandit_packages())

      html = view |> form("form", %{version: "1.5.8"}) |> render_change()

      assert html =~ "✓ bandit 1.5.8 is not affected"
      assert html =~ "text-success"
    end

    test "a version below every range takes the default", %{conn: conn} do
      {:ok, view, _html} = mount(conn, bandit_packages())

      html = view |> form("form", %{version: "1.0.0"}) |> render_change()

      assert html =~ "✓ bandit 1.0.0 is not affected"
    end

    test "unparseable input never gets a coloured verdict", %{conn: conn} do
      {:ok, view, _html} = mount(conn, bandit_packages())

      html = view |> form("form", %{version: "bandit-1.4"}) |> render_change()

      assert html =~ "not a recognizable version"
      refute html =~ "text-error"
      refute html =~ "text-success"
    end

    test "clearing the input drops the verdict", %{conn: conn} do
      {:ok, view, _html} = mount(conn, bandit_packages())

      view |> form("form", %{version: "1.5.4"}) |> render_change()
      html = view |> form("form", %{version: ""}) |> render_change()

      assert html =~ "type your bandit version to check"
    end
  end

  describe "unknown is its own verdict, never dressed as safe" do
    test "a version an unknown range covers reports unknown", %{conn: conn} do
      packages = [package(%{"versions" => [semver("0.1.0", "1.0.0", "unknown")]})]
      {:ok, view, _html} = mount(conn, packages)

      html = view |> form("form", %{version: "0.5.0"}) |> render_change()

      assert html =~ "doesn&#39;t say whether this version is affected"
      assert html =~ "text-warning"
      refute html =~ "text-success"
    end

    test "a version no range covers takes an unknown default", %{conn: conn} do
      packages = [
        package(%{"versions" => [semver("1.0.0", "2.0.0")], "default_status" => "unknown"})
      ]

      {:ok, view, _html} = mount(conn, packages)

      html = view |> form("form", %{version: "5.0.0"}) |> render_change()

      assert html =~ "doesn&#39;t say whether this version is affected"
      refute html =~ "text-success"
    end
  end

  describe "defaultStatus is honoured, whatever it says" do
    test "an affected-by-default record reports affected outside its ranges", %{conn: conn} do
      packages = [
        package(%{
          "versions" => [semver("1.0.0", "2.0.0", "unaffected")],
          "default_status" => "affected"
        })
      ]

      {:ok, view, _html} = mount(conn, packages)

      assert view |> form("form", %{version: "1.5.0"}) |> render_change() =~ "is not affected"
      assert view |> form("form", %{version: "9.9.9"}) |> render_change() =~ "is affected"
    end
  end

  describe "a product with no orderable versions takes no input" do
    defp git_packages do
      [
        package(%{
          "purl" => "pkg:github/acme/lib",
          "bare_name" => "lib",
          "askable?" => false,
          "versions" => [
            %{
              "version" => String.duplicate("a", 40),
              "lessThan" => String.duplicate("b", 40),
              "status" => "affected",
              "versionType" => "git"
            }
          ]
        })
      ]
    end

    test "renders the ranges instead of a version box", %{conn: conn} do
      {:ok, _view, html} = mount(conn, git_packages())

      refute html =~ "<input"
      assert html =~ "can&#39;t be compared automatically"
      # The same block the Affected card renders: shortened shas, full in title.
      assert html =~ String.slice(String.duplicate("a", 40), 0, 7)
      assert html =~ ~s(title="#{String.duplicate("a", 40)}")
    end
  end

  describe "OTP release vocabulary" do
    defp otp_packages do
      [
        package(%{
          "purl" => "pkg:github/erlang/otp",
          "bare_name" => "ssh",
          "otp_release?" => true,
          "otp_package?" => true,
          "versions" => [
            %{
              "version" => "OTP-26.0",
              "lessThan" => "OTP-26.2.5.6",
              "status" => "affected",
              "versionType" => "otp"
            }
          ]
        })
      ]
    end

    test "the placeholder reads 'Erlang release, e.g. …'", %{conn: conn} do
      {:ok, _view, html} = mount(conn, otp_packages())
      assert html =~ "Erlang release, e.g."
    end

    test "the tag is accepted with or without its OTP- prefix", %{conn: conn} do
      {:ok, view, _html} = mount(conn, otp_packages())

      assert view |> form("form", %{version: "OTP-26.2.5.2"}) |> render_change() =~
               "✗ ssh in Erlang 26.2.5.2 is affected"

      assert view |> form("form", %{version: "26.2.5.2"}) |> render_change() =~
               "✗ ssh in Erlang 26.2.5.2 is affected"
    end

    test "a typed R release is answered as unsupported, never as safe", %{conn: conn} do
      {:ok, view, _html} = mount(conn, otp_packages())

      for typed <- ~w(R16B03 OTP_R13B03 R10B-1a) do
        html = view |> form("form", %{version: typed}) |> render_change()

        assert html =~ "R releases aren&#39;t supported"
        refute html =~ "is not affected"
      end
    end

    # A leading `R` only means the R series to an OTP checker.
    test "an R-prefixed input elsewhere is just an unrecognizable version", %{conn: conn} do
      packages = [
        package(%{
          "purl" => "pkg:hex/acme",
          "bare_name" => "acme",
          "versions" => [semver("1.0.0", "2.0.0")]
        })
      ]

      {:ok, view, _html} = mount(conn, packages)

      html = view |> form("form", %{version: "R16B03"}) |> render_change()

      assert html =~ "not a recognizable version"
      refute html =~ "R releases"
    end
  end

  describe "package selector" do
    defp packages(count) do
      for i <- 1..count do
        package(%{
          "purl" => "pkg:hex/pkg#{i}",
          "bare_name" => "pkg#{i}",
          "versions" => [semver("1.0.0", "2.0.0")]
        })
      end
    end

    test "a single package renders no selector", %{conn: conn} do
      {:ok, _view, html} = mount(conn, packages(1))

      refute html =~ "select-package"
    end

    test "2–4 packages render pills, defaulting to the first", %{conn: conn} do
      {:ok, _view, html} = mount(conn, packages(3))

      assert html =~ "pkg:hex/pkg1"
      assert html =~ "pkg:hex/pkg3"
      assert html =~ "rounded-full"
      assert html =~ "type your pkg1 version to check"
    end

    test "5+ packages render a select", %{conn: conn} do
      {:ok, _view, html} = mount(conn, packages(5))

      assert html =~ "<select"
      refute html =~ "rounded-full"
    end

    test "switching package swaps the verdict but keeps the typed input", %{conn: conn} do
      packages = [
        package(%{
          "purl" => "pkg:hex/a",
          "bare_name" => "a",
          "versions" => [semver("1.0.0", "2.0.0")]
        }),
        package(%{
          "purl" => "pkg:hex/b",
          "bare_name" => "b",
          "versions" => [semver("5.0.0", "6.0.0")]
        })
      ]

      {:ok, view, _html} = mount(conn, packages)

      assert view |> form("form", %{version: "1.5.0"}) |> render_change() =~
               "✗ a 1.5.0 is affected"

      html = view |> element(~s{button[phx-value-index="1"]}) |> render_click()

      assert html =~ "✓ b 1.5.0 is not affected"
      assert html =~ ~s(value="1.5.0")
    end
  end
end
