# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.ChildOrderTest do
  @moduledoc """
  A case's packages, their channels and their boundary facts come back in one
  order every time, and the in-memory `sort/1` of each agrees with the
  database's.
  """

  use Varsel.DataCase, async: true

  alias Varsel.Cases
  alias Varsel.Cases.AffectedPackage
  alias Varsel.Cases.PackageChannel
  alias Varsel.Cases.VersionEvent
  alias Varsel.Fixtures

  setup do
    poc = Fixtures.register_user("child_order_poc", :poc)
    %{poc: poc, case_record: Fixtures.open_case(poc)}
  end

  defp loaded(case_record, poc) do
    Cases.get_case!(case_record.id,
      actor: poc,
      load: [affected_packages: [channels: [:purl], version_events: []]]
    )
  end

  test "packages sort by vendor and product without case, then repository URL", %{
    poc: poc,
    case_record: case_record
  } do
    for attrs <- [
          %{vendor: "beta", product: "x", repo_url: nil},
          %{vendor: "acme", product: "Zeta", repo_url: nil},
          %{vendor: "beta", product: "x", repo_url: "https://github.com/beta/x"},
          %{vendor: "Acme", product: "alpha", repo_url: nil}
        ] do
      Fixtures.add_affected_package(poc, case_record, attrs)
    end

    packages = loaded(case_record, poc).affected_packages

    assert Enum.map(packages, &{&1.vendor, &1.product, &1.repo_url && to_string(&1.repo_url)}) ==
             [
               {"Acme", "alpha", nil},
               {"acme", "Zeta", nil},
               {"beta", "x", "https://github.com/beta/x"},
               {"beta", "x", nil}
             ]

    assert AffectedPackage.sort(Enum.reverse(packages)) == packages
  end

  test "channels sort by purl, services after them, the repository last", %{
    poc: poc,
    case_record: case_record
  } do
    package = Fixtures.add_affected_package(poc, case_record)

    for attrs <- [
          %{kind: :service, domain: "acme.example"},
          %{purl_type: "npm", name: "acme_lib"},
          %{purl_type: "hex", name: "acme_lib"}
        ] do
      Cases.add_package_channel!(
        Map.merge(%{case_id: case_record.id, affected_package_id: package.id}, attrs),
        actor: poc
      )
    end

    [%{channels: channels}] = loaded(case_record, poc).affected_packages

    assert Enum.map(channels, &(&1.purl || &1.domain)) == [
             "pkg:hex/acme_lib",
             "pkg:npm/acme_lib",
             "acme.example",
             "pkg:github/acme/acme_lib"
           ]

    assert PackageChannel.sort(Enum.reverse(channels)) == channels
  end

  test "boundary facts sort introductions first, then by commit", %{
    poc: poc,
    case_record: case_record
  } do
    package = Fixtures.add_affected_package(poc, case_record)

    for {event, char} <- [fixed: "b", introduced: "c", introduced: "a"] do
      Cases.add_version_event!(
        %{
          case_id: case_record.id,
          affected_package_id: package.id,
          event: event,
          commit_sha: String.duplicate(char, 40)
        },
        actor: poc
      )
    end

    [%{version_events: events}] = loaded(case_record, poc).affected_packages

    assert Enum.map(events, &{&1.event, String.first(&1.commit_sha)}) == [
             {:introduced, "a"},
             {:introduced, "c"},
             {:fixed, "b"}
           ]

    assert VersionEvent.sort(Enum.reverse(events)) == events
  end
end
