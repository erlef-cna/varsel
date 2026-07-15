# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.ProposalTest do
  use Varsel.DataCase, async: false

  alias Ash.Error.Forbidden
  alias Varsel.Cases
  alias Varsel.Cases.AffectedPackage
  alias Varsel.Cases.CaseReference
  alias Varsel.Cases.Projection
  alias Varsel.Cases.Proposal
  alias Varsel.Cases.VersionEvent
  alias Varsel.Fixtures

  require Ash.Query

  setup do
    poc = Fixtures.register_user("proposal_poc", :poc)
    supporter = Fixtures.register_user("proposal_supporter", :supporter)
    case_record = Fixtures.open_case(poc, %{title: "Original title"})

    %{poc: poc, supporter: supporter, case: case_record}
  end

  defp propose_set(actor, case_record, field, value, extra \\ %{}) do
    Cases.create_case_proposal!(
      Map.merge(
        %{
          case_id: case_record.id,
          target: :case,
          operation: :set,
          field_name: field,
          proposed_value: %{"value" => value}
        },
        extra
      ),
      actor: actor
    )
  end

  describe ":propose validation" do
    test "accepts a well-formed :set on the case", %{poc: poc, case: case_record} do
      proposal = propose_set(poc, case_record, "title", "Better title")

      assert proposal.state == :open
      assert proposal.author_id == poc.id
    end

    test "rejects a field outside the allowlist", %{poc: poc, case: case_record} do
      assert {:error, error} =
               Cases.create_case_proposal(
                 %{
                   case_id: case_record.id,
                   target: :case,
                   operation: :set,
                   field_name: "state",
                   proposed_value: %{"value" => "published"}
                 },
                 actor: poc
               )

      assert Exception.message(error) =~ "not a proposable field"
    end

    test "type-checks the proposed value against the real attribute type", %{
      poc: poc,
      case: case_record
    } do
      assert {:error, error} =
               Cases.create_case_proposal(
                 %{
                   case_id: case_record.id,
                   target: :case,
                   operation: :set,
                   field_name: "cvss_v4",
                   proposed_value: %{"value" => "not a vector"}
                 },
                 actor: poc
               )

      assert Exception.message(error) =~ "does not accept the proposed value"

      assert %Proposal{} =
               propose_set(
                 poc,
                 case_record,
                 "cvss_v4",
                 "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N"
               )
    end

    test "rejects a value without the envelope", %{poc: poc, case: case_record} do
      assert {:error, error} =
               Cases.create_case_proposal(
                 %{
                   case_id: case_record.id,
                   target: :case,
                   operation: :set,
                   field_name: "title",
                   proposed_value: %{"title" => "raw"}
                 },
                 actor: poc
               )

      assert Exception.message(error) =~ "envelope"
    end

    test "rejects insert/delete against the case itself", %{poc: poc, case: case_record} do
      assert {:error, error} =
               Cases.create_case_proposal(
                 %{
                   case_id: case_record.id,
                   target: :case,
                   operation: :delete,
                   target_id: case_record.id
                 },
                 actor: poc
               )

      assert Exception.message(error) =~ "cannot be inserted or deleted"
    end

    test "rejects a target row belonging to a different case", %{poc: poc, case: case_record} do
      other_case = Fixtures.open_case(poc, %{title: "Other"})
      other_package = Fixtures.add_affected_package(poc, other_case)

      assert {:error, error} =
               Cases.create_case_proposal(
                 %{
                   case_id: case_record.id,
                   target: :affected_package,
                   operation: :set,
                   target_id: other_package.id,
                   field_name: "vendor",
                   proposed_value: %{"value" => "acme"}
                 },
                 actor: poc
               )

      assert Exception.message(error) =~ "different case"
    end

    test "validates :insert payload keys and types", %{poc: poc, case: case_record} do
      assert {:error, error} =
               Cases.create_case_proposal(
                 %{
                   case_id: case_record.id,
                   target: :reference,
                   operation: :insert,
                   proposed_value: %{
                     "value" => %{"url" => "https://x.example", "case_id" => case_record.id}
                   }
                 },
                 actor: poc
               )

      assert Exception.message(error) =~ "not a proposable field"
    end

    test "proposals cannot be created on a closed case", %{poc: poc, case: case_record} do
      Cases.close_case!(case_record, %{}, actor: poc)

      assert {:error, error} =
               Cases.create_case_proposal(
                 %{
                   case_id: case_record.id,
                   target: :case,
                   operation: :set,
                   field_name: "title",
                   proposed_value: %{"value" => "x"}
                 },
                 actor: poc
               )

      assert Exception.message(error) =~ "closed"
    end

    test "an unassigned supporter cannot propose; an assigned one can", %{
      poc: poc,
      supporter: supporter,
      case: case_record
    } do
      params = %{
        case_id: case_record.id,
        target: :case,
        operation: :set,
        field_name: "title",
        proposed_value: %{"value" => "From supporter"}
      }

      assert {:error, %Forbidden{}} =
               Cases.create_case_proposal(params, actor: supporter)

      Cases.assign_case_user!(%{case_id: case_record.id, user_id: supporter.id}, actor: poc)

      assert %Proposal{} = Cases.create_case_proposal!(params, actor: supporter)
    end
  end

  describe ":accept — :set" do
    test "applies the value to the case with the approver as paper-trail actor", %{
      poc: poc,
      supporter: supporter,
      case: case_record
    } do
      Cases.assign_case_user!(%{case_id: case_record.id, user_id: supporter.id}, actor: poc)
      proposal = propose_set(supporter, case_record, "title", "Better title")

      accepted = Cases.accept_case_proposal!(proposal, %{}, actor: poc)
      assert accepted.state == :accepted
      assert accepted.resolved_by_id == poc.id
      assert accepted.resolved_at

      case_record = Ash.get!(Cases.Case, case_record.id, authorize?: false)
      assert case_record.title == "Better title"

      version =
        Cases.Case.Version
        |> Ash.Query.filter(version_source_id == ^case_record.id and version_action_name == :apply_proposal)
        |> Ash.read_one!(authorize?: false)

      assert version.user_id == poc.id
    end

    test "applies a :set on a child row", %{poc: poc, case: case_record} do
      package = Fixtures.add_affected_package(poc, case_record)

      proposal =
        Cases.create_case_proposal!(
          %{
            case_id: case_record.id,
            target: :affected_package,
            operation: :set,
            target_id: package.id,
            field_name: "modules",
            proposed_value: %{"value" => ["ssh"]}
          },
          actor: poc
        )

      Cases.accept_case_proposal!(proposal, %{}, actor: poc)

      assert Ash.get!(AffectedPackage, package.id, authorize?: false).modules == ["ssh"]
    end

    test "supersedes competing proposals for the same field", %{poc: poc, case: case_record} do
      first = propose_set(poc, case_record, "title", "Title A")
      second = propose_set(poc, case_record, "title", "Title B")
      unrelated = propose_set(poc, case_record, "description_md", "Something")

      Cases.accept_case_proposal!(first, %{}, actor: poc)

      assert Ash.get!(Proposal, second.id, authorize?: false).state == :superseded
      assert Ash.get!(Proposal, unrelated.id, authorize?: false).state == :open
    end

    test "a counter-proposal supersedes its parent when accepted", %{poc: poc, case: case_record} do
      parent = propose_set(poc, case_record, "title", "Parent title")

      counter =
        propose_set(poc, case_record, "title", "Counter title", %{parent_proposal_id: parent.id})

      Cases.accept_case_proposal!(counter, %{}, actor: poc)

      assert Ash.get!(Proposal, parent.id, authorize?: false).state == :superseded
      assert Ash.get!(Cases.Case, case_record.id, authorize?: false).title == "Counter title"
    end

    test "cannot accept twice (stale write)", %{poc: poc, case: case_record} do
      proposal = propose_set(poc, case_record, "title", "Once")
      Cases.accept_case_proposal!(proposal, %{}, actor: poc)

      assert {:error, _error} = Cases.accept_case_proposal(proposal, %{}, actor: poc)
    end

    test "accept is blocked outside draft/review", %{poc: poc, case: case_record} do
      proposal = propose_set(poc, case_record, "title", "Later")

      case_record = Cases.request_case_review!(case_record, actor: poc)
      _case_record = Cases.approve_case!(case_record, actor: poc)

      assert {:error, error} = Cases.accept_case_proposal(proposal, %{}, actor: poc)
      assert Exception.message(error) =~ "reopen the case"
    end
  end

  describe "nested insert payloads" do
    defp propose_package(actor, case_record, payload) do
      Cases.create_case_proposal(
        %{
          case_id: case_record.id,
          target: :affected_package,
          operation: :insert,
          proposed_value: %{"value" => payload},
          reasoning: "one-shot intake"
        },
        actor: actor
      )
    end

    defp otp_payload do
      %{
        "vendor" => "Erlang",
        "product" => "OTP",
        "repo_url" => "https://github.com/erlang/otp",
        "program_files" => ["lib/xmerl/src/xmerl_scan.erl"],
        "channels" => [%{"purl_type" => "otp", "name" => "xmerl"}],
        "version_events" => [
          %{"event" => "fixed", "version" => "27.3.4"},
          %{"event" => "fixed", "version" => "26.2.5.12"}
        ]
      }
    end

    test "accept creates the package with its channels and version events", %{
      poc: poc,
      case: case_record
    } do
      {:ok, proposal} = propose_package(poc, case_record, otp_payload())
      accepted = Cases.accept_case_proposal!(proposal, %{}, actor: poc)

      package =
        Ash.get!(AffectedPackage, accepted.applied_target_id,
          load: [:channels, :version_events],
          authorize?: false
        )

      assert package.product == "OTP"
      assert package.program_files == ["lib/xmerl/src/xmerl_scan.erl"]

      assert [channel] = package.channels
      assert channel.purl_type == :otp
      assert channel.name == "xmerl"

      assert package.version_events |> Enum.map(& &1.version) |> Enum.sort() ==
               ["26.2.5.12", "27.3.4"]

      assert Enum.all?(package.version_events, &(&1.case_id == case_record.id))
    end

    test "nested rows validate against the child allowlist", %{poc: poc, case: case_record} do
      payload = Map.put(otp_payload(), "channels", [%{"purl_type" => "otp", "case_id" => "x"}])

      assert {:error, error} = propose_package(poc, case_record, payload)
      assert Exception.message(error) =~ "not a proposable field"
    end

    test "nested values are cast through the child attribute types", %{
      poc: poc,
      case: case_record
    } do
      payload = Map.put(otp_payload(), "channels", [%{"purl_type" => "carrier-pigeon"}])

      assert {:error, error} = propose_package(poc, case_record, payload)
      assert Exception.message(error) =~ "does not accept the proposed value"
    end

    test "nested collections must be lists of row objects", %{poc: poc, case: case_record} do
      payload = Map.put(otp_payload(), "version_events", %{"event" => "fixed"})

      assert {:error, error} = propose_package(poc, case_record, payload)
      assert Exception.message(error) =~ "must be a list of row objects"
    end

    test "a failing nested row rolls back the whole accept", %{poc: poc, case: case_record} do
      # Passes creation-time casting (all keys allowed, types fine) but fails
      # the channel's own apply-time validation: non-hosted channels need a
      # name.
      payload = Map.put(otp_payload(), "channels", [%{"purl_type" => "otp"}])

      {:ok, proposal} = propose_package(poc, case_record, payload)
      assert {:error, _error} = Cases.accept_case_proposal(proposal, %{}, actor: poc)

      # Nothing was created and the proposal stayed open.
      assert [] =
               Ash.read!(AffectedPackage, authorize?: false)

      assert Ash.get!(Proposal, proposal.id, authorize?: false).state == :open
    end

    test "the projection shows nested phantom children", %{poc: poc, case: case_record} do
      {:ok, _proposal} = propose_package(poc, case_record, otp_payload())

      case_record =
        Ash.get!(Varsel.Cases.Case, case_record.id,
          load: [
            :proposals,
            :references,
            :credits,
            weaknesses: [:weakness],
            impacts: [:attack_pattern],
            affected_packages: [:channels, :version_events]
          ],
          authorize?: false
        )

      projection = Projection.project(case_record)

      assert [package] = projection.case.affected_packages
      assert package.product == "OTP"
      assert [channel] = package.channels
      assert channel.purl_type == :otp
      assert channel.name == "xmerl"
      assert length(package.version_events) == 2
    end
  end

  describe ":accept — :insert / :delete" do
    test "insert creates the row and records applied_target_id", %{poc: poc, case: case_record} do
      proposal =
        Cases.create_case_proposal!(
          %{
            case_id: case_record.id,
            target: :reference,
            operation: :insert,
            proposed_value: %{
              "value" => %{
                "url" => "https://example.com/advisory",
                "tags" => ["vendor-advisory"],
                "position" => 0
              }
            }
          },
          actor: poc
        )

      accepted = Cases.accept_case_proposal!(proposal, %{}, actor: poc)

      reference = Ash.get!(CaseReference, accepted.applied_target_id, authorize?: false)
      assert reference.url == "https://example.com/advisory"
      assert reference.case_id == case_record.id
    end

    test "insert of a version event under a package via target_id", %{poc: poc, case: case_record} do
      package = Fixtures.add_affected_package(poc, case_record)
      sha = String.duplicate("a", 40)

      proposal =
        Cases.create_case_proposal!(
          %{
            case_id: case_record.id,
            target: :version_event,
            operation: :insert,
            target_id: package.id,
            proposed_value: %{"value" => %{"event" => "fixed", "commit_sha" => sha}}
          },
          actor: poc
        )

      accepted = Cases.accept_case_proposal!(proposal, %{}, actor: poc)

      event = Ash.get!(VersionEvent, accepted.applied_target_id, authorize?: false)
      assert event.event == :fixed
      assert event.commit_sha == sha
      assert event.affected_package_id == package.id
      assert event.case_id == case_record.id
    end

    test "delete removes the row and supersedes proposals on it", %{poc: poc, case: case_record} do
      package = Fixtures.add_affected_package(poc, case_record)

      pending_set =
        Cases.create_case_proposal!(
          %{
            case_id: case_record.id,
            target: :affected_package,
            operation: :set,
            target_id: package.id,
            field_name: "vendor",
            proposed_value: %{"value" => "someone"}
          },
          actor: poc
        )

      delete_proposal =
        Cases.create_case_proposal!(
          %{
            case_id: case_record.id,
            target: :affected_package,
            operation: :delete,
            target_id: package.id
          },
          actor: poc
        )

      Cases.accept_case_proposal!(delete_proposal, %{}, actor: poc)

      assert {:error, _} = Ash.get(AffectedPackage, package.id, authorize?: false)
      assert Ash.get!(Proposal, pending_set.id, authorize?: false).state == :superseded
    end

    test "accepting a :set whose row was deleted fails cleanly", %{poc: poc, case: case_record} do
      package = Fixtures.add_affected_package(poc, case_record)

      proposal =
        Cases.create_case_proposal!(
          %{
            case_id: case_record.id,
            target: :affected_package,
            operation: :set,
            target_id: package.id,
            field_name: "vendor",
            proposed_value: %{"value" => "someone"}
          },
          actor: poc
        )

      # The destroy sweeps the proposal; force it back open with raw SQL to
      # exercise the accept-time backstop (simulating a missed sweep).
      Cases.remove_affected_package!(package, actor: poc)

      Varsel.Repo.query!(
        "UPDATE case_proposals SET state = 'open' WHERE id = $1",
        [Ecto.UUID.dump!(proposal.id)]
      )

      proposal = Ash.get!(Proposal, proposal.id, authorize?: false)
      assert proposal.state == :open

      assert {:error, error} = Cases.accept_case_proposal(proposal, %{}, actor: poc)
      assert Exception.message(error) =~ "no longer exists"
    end
  end

  describe ":decline / :withdraw" do
    test "decline records the note and resolver", %{poc: poc, case: case_record} do
      proposal = propose_set(poc, case_record, "title", "Nope")

      declined =
        Cases.decline_case_proposal!(proposal, %{resolution_note: "not accurate"}, actor: poc)

      assert declined.state == :declined
      assert declined.resolution_note == "not accurate"
      assert declined.resolved_by_id == poc.id
    end

    test "the author can withdraw; others cannot", %{
      poc: poc,
      supporter: supporter,
      case: case_record
    } do
      Cases.assign_case_user!(%{case_id: case_record.id, user_id: supporter.id}, actor: poc)
      other_supporter = Fixtures.register_user("other_supporter", :supporter)
      Cases.assign_case_user!(%{case_id: case_record.id, user_id: other_supporter.id}, actor: poc)

      proposal = propose_set(supporter, case_record, "title", "Mine")

      assert {:error, %Forbidden{}} =
               Cases.withdraw_case_proposal(proposal, actor: other_supporter)

      withdrawn = Cases.withdraw_case_proposal!(proposal, actor: supporter)
      assert withdrawn.state == :withdrawn
    end
  end
end
