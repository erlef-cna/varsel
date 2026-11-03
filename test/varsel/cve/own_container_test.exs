# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CVE.OwnContainerTest do
  use ExUnit.Case, async: true

  alias Varsel.CVE.OwnContainer

  @other_org_id "1ad8a6c6-5a6e-4a3b-9b1e-6c2b2c8e4d10"
  @cisa_org_id "8254265b-2729-46b6-b9e3-3dfca2d5bfca"

  defp record(assigner_org_id, containers) do
    %{"cveMetadata" => %{"assignerOrgId" => assigner_org_id}, "containers" => containers}
  end

  defp container(org_id, title), do: %{"providerMetadata" => %{"orgId" => org_id}, "title" => title}

  test "in a record this CNA assigned, it is the CNA container" do
    cna = container(OwnContainer.org_id(), "ours")

    record =
      record(OwnContainer.org_id(), %{"cna" => cna, "adp" => [container(@cisa_org_id, "CISA")]})

    refute OwnContainer.upstream?(record)
    assert OwnContainer.get(record) == cna

    assert OwnContainer.put(record, %{cna | "title" => "new"})["containers"]["cna"]["title"] ==
             "new"
  end

  test "in an upstream record, it is the ADP entry with this CNA's orgId" do
    ours = container(OwnContainer.org_id(), "ours")
    cisa = container(@cisa_org_id, "CISA")
    upstream_cna = container(@other_org_id, "upstream")
    record = record(@other_org_id, %{"cna" => upstream_cna, "adp" => [ours, cisa]})

    assert OwnContainer.upstream?(record)
    assert OwnContainer.get(record) == ours

    updated = OwnContainer.put(record, %{ours | "title" => "new"})

    assert updated["containers"]["cna"] == upstream_cna
    assert updated["containers"]["adp"] == [cisa, %{ours | "title" => "new"}]
  end

  test "an upstream record without this CNA's entry gets one" do
    record = record(@other_org_id, %{"cna" => container(@other_org_id, "upstream")})
    ours = container(OwnContainer.org_id(), "ours")

    assert OwnContainer.get(record) == nil
    assert OwnContainer.get(OwnContainer.put(record, ours)) == ours
  end
end
