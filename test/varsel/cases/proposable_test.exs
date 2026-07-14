# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.ProposableTest do
  use ExUnit.Case, async: true

  alias Ash.Resource.Info
  alias Varsel.Cases.Proposable
  alias Varsel.Cases.Proposal.Target

  @resources [
    Varsel.Cases.Case,
    Varsel.Cases.AffectedPackage,
    Varsel.Cases.PackageChannel,
    Varsel.Cases.VersionEvent,
    Varsel.Cases.CaseReference,
    Varsel.Cases.CaseCredit,
    Varsel.Cases.CaseWeakness,
    Varsel.Cases.CaseImpact
  ]

  test "every proposable field exists as a writable attribute on its resource" do
    for resource <- @resources,
        field <- Proposable.fields(resource) ++ Proposable.insert_extra_fields(resource) do
      attribute = Info.attribute(resource, field)

      assert attribute, "#{inspect(resource)} has no attribute #{field}"
      assert attribute.writable?, "#{inspect(resource)}.#{field} is not writable"
    end
  end

  test "set_fields are a subset of fields" do
    for resource <- @resources do
      assert Proposable.set_fields(resource) -- Proposable.fields(resource) == []
    end
  end

  test "every proposal target resolves to a resource with the required internal actions" do
    for target <- Target.values(), target != :case do
      resource = Target.resource(target)
      actions = resource |> Info.actions() |> Enum.map(& &1.name)

      assert :apply_proposal_insert in actions,
             "#{inspect(resource)} lacks :apply_proposal_insert"

      assert :apply_proposal_delete in actions,
             "#{inspect(resource)} lacks :apply_proposal_delete"

      if Proposable.set_fields(resource) != [] do
        assert :apply_proposal in actions, "#{inspect(resource)} lacks :apply_proposal"
      end
    end
  end
end
