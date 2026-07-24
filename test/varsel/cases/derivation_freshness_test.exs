# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.DerivationFreshnessTest do
  use Varsel.DataCase, async: false

  alias Varsel.Cases
  alias Varsel.Cases.DerivationFreshness
  alias Varsel.Fixtures
  alias Varsel.Test.StubGitBackend

  @repo "https://github.com/x/y"
  @fix_sha "a3253fb4fc7145aeb403537af1c24d3a8d51ffb1"

  setup do
    poc = Fixtures.register_user("freshness_poc", :poc)
    StubGitBackend.stub_tags(%{{@repo, @fix_sha} => ["v2.10.0"]})
    Application.put_env(:varsel, :hex_stub_packages, ["acme_lib"])
    on_exit(fn -> Application.delete_env(:varsel, :hex_stub_packages) end)

    %{poc: poc}
  end

  defp package_with_intro(poc, opts \\ []) do
    case_record = Fixtures.open_case(poc, %{title: "t"})

    package =
      Fixtures.add_affected_package(poc, case_record, %{
        vendor: "acme",
        product: "acme_lib",
        repo_url: Keyword.get(opts, :repo_url, @repo)
      })

    Cases.add_version_event!(
      %{
        case_id: case_record.id,
        affected_package_id: package.id,
        event: :introduced,
        version: "0"
      },
      actor: poc
    )

    if Keyword.get(opts, :fixed) do
      Cases.add_version_event!(
        %{
          case_id: case_record.id,
          affected_package_id: package.id,
          event: :fixed,
          commit_sha: @fix_sha
        },
        actor: poc
      )
    end

    {case_record, package}
  end

  defp reload(case_record, poc) do
    [package] =
      Cases.get_case!(case_record.id,
        load: [affected_packages: [:channels, :version_events]],
        actor: poc
      ).affected_packages

    package
  end

  test "a never-refreshed package is stale", %{poc: poc} do
    {case_record, _} = package_with_intro(poc)

    assert DerivationFreshness.stale?(reload(case_record, poc))
  end

  test "a freshly refreshed package is not stale", %{poc: poc} do
    {case_record, _} = package_with_intro(poc, fixed: true)
    {:ok, _} = Cases.refresh_case_derivation(case_record, actor: poc)

    refute DerivationFreshness.stale?(reload(case_record, poc))
  end

  test "a fact added after the last refresh makes it stale again", %{poc: poc} do
    {case_record, package} = package_with_intro(poc, fixed: true)
    {:ok, _} = Cases.refresh_case_derivation(case_record, actor: poc)
    refute DerivationFreshness.stale?(reload(case_record, poc))

    Cases.add_version_event!(
      %{
        case_id: case_record.id,
        affected_package_id: package.id,
        event: :fixed,
        version: "3.0.0"
      },
      actor: poc
    )

    assert DerivationFreshness.stale?(reload(case_record, poc))
  end

  test "missing_versions? is true when a fresh derivation yields nothing", %{poc: poc} do
    # No repo_url and no channel: the introduced boundary has nowhere to derive.
    {case_record, _} = package_with_intro(poc, repo_url: nil)
    {:ok, _} = Cases.refresh_case_derivation(case_record, actor: poc)

    package = reload(case_record, poc)
    refute DerivationFreshness.stale?(package)
    assert DerivationFreshness.missing_versions?(package)
  end

  test "missing_versions? is false when the git entry derives a range", %{poc: poc} do
    {case_record, _} = package_with_intro(poc, fixed: true)
    {:ok, _} = Cases.refresh_case_derivation(case_record, actor: poc)

    refute DerivationFreshness.missing_versions?(reload(case_record, poc))
  end

  test "missing_versions? is false while the cache is stale", %{poc: poc} do
    # Staleness is reported on its own; an out-of-date cache says nothing
    # reliable about the derived versions, so missing_versions? stays quiet.
    {case_record, _} = package_with_intro(poc, repo_url: nil)

    package = reload(case_record, poc)
    assert DerivationFreshness.stale?(package)
    refute DerivationFreshness.missing_versions?(package)
  end
end
