# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Case.Changes.RefreshDerivationTest do
  use Varsel.DataCase, async: false

  alias Varsel.Cases
  alias Varsel.Fixtures
  alias Varsel.Test.StubGitBackend

  @repo "https://github.com/x/y"
  @intro_sha "1111111111111111111111111111111111111111"

  setup do
    poc = Fixtures.register_user("refresh_derivation_poc", :poc)

    StubGitBackend.stub_tags(%{
      {@repo, @intro_sha} => ["v1.0.0", "v2.10.0"]
    })

    Application.put_env(:varsel, :hex_stub_packages, ["acme_lib", "acme_other"])
    on_exit(fn -> Application.delete_env(:varsel, :hex_stub_packages) end)

    %{poc: poc}
  end

  defp case_with_packages(poc, products) do
    case_record = Fixtures.open_case(poc, %{title: "t"})

    for product <- products do
      package =
        Fixtures.add_affected_package(poc, case_record, %{
          vendor: "acme",
          product: product,
          repo_url: @repo
        })

      Cases.add_version_event!(
        %{
          case_id: case_record.id,
          affected_package_id: package.id,
          event: :introduced,
          commit_sha: @intro_sha
        },
        actor: poc
      )
    end

    case_record
  end

  test "by default derives from the cached git state", %{poc: poc} do
    case_record = case_with_packages(poc, ["acme_lib"])

    {:ok, _} = Cases.refresh_case_derivation(case_record, actor: poc)

    assert StubGitBackend.refreshed_repos() == []
  end

  test "refresh brings each repository up to date, once per distinct URL", %{poc: poc} do
    case_record = case_with_packages(poc, ["acme_lib", "acme_other"])

    {:ok, _} = Cases.refresh_case_derivation(case_record, %{refresh: true}, actor: poc)

    assert StubGitBackend.refreshed_repos() == [@repo]
  end
end
