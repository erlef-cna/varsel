# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases do
  @moduledoc false
  use Ash.Domain,
    otp_app: :varsel,
    extensions: [AshAdmin.Domain, AshAi, AshGraphql.Domain, AshPaperTrail.Domain]

  alias Varsel.Cases.AffectedPackage
  alias Varsel.Cases.Case
  alias Varsel.Cases.CaseAssignment
  alias Varsel.Cases.CaseCredit
  alias Varsel.Cases.CaseImpact
  alias Varsel.Cases.CaseReference
  alias Varsel.Cases.CaseWeakness
  alias Varsel.Cases.Comment
  alias Varsel.Cases.PackageChannel
  alias Varsel.Cases.Proposal
  alias Varsel.Cases.VersionEvent

  admin do
    show? true
  end

  tools do
    # Opening a fresh draft is the one lifecycle action exposed to the agent:
    # it creates the empty workspace the agent then fills via proposals, rather
    # than advancing or resolving an existing case (POC-only, same as the UI).
    tool :open_case, Case, :open

    # Case reading + previews (policy-gated: POC or assigned; requires an API key actor).
    tool :list_cases, Case, :list_cases do
      load [:cve_id]
    end

    tool :get_case, Case, :read do
      load [
        :cve_id,
        :assignments,
        :references,
        :credits,
        :weaknesses,
        :impacts,
        affected_packages: [:channels, :version_events]
      ]
    end

    tool :render_case_preview, Case, :render_preview
    tool :refresh_case_derivation, Case, :refresh_derivation

    # Proposal workflow: discover → propose → discuss. Deliberately no
    # accept/decline/lifecycle tools — resolving proposals and moving cases
    # through their lifecycle stays in the human UI.
    tool :list_case_proposals, Proposal, :list_for_case
    tool :list_open_case_proposals, Proposal, :list_open_for_case

    # One typed propose_* tool per field/child kind (the generic :propose stays
    # private; the agent picks the tool that names what it is changing).
    tool :propose_title, Proposal, :propose_title
    tool :propose_description, Proposal, :propose_description
    tool :propose_workarounds, Proposal, :propose_workarounds
    tool :propose_configurations, Proposal, :propose_configurations
    tool :propose_solutions, Proposal, :propose_solutions
    tool :propose_discovery, Proposal, :propose_discovery
    tool :propose_cvss, Proposal, :propose_cvss
    tool :propose_date_public, Proposal, :propose_date_public
    tool :propose_timeline, Proposal, :propose_timeline
    tool :propose_cna_override, Proposal, :propose_cna_override
    tool :propose_weakness, Proposal, :propose_weakness
    tool :propose_impact, Proposal, :propose_impact
    tool :propose_reference, Proposal, :propose_reference
    tool :propose_credit, Proposal, :propose_credit
    tool :propose_affected_package, Proposal, :propose_affected_package
    tool :propose_otp_affected_package, Proposal, :propose_otp_affected_package
    tool :propose_elixir_affected_package, Proposal, :propose_elixir_affected_package
    tool :propose_gleam_affected_package, Proposal, :propose_gleam_affected_package
    tool :propose_package_channel, Proposal, :propose_package_channel
    tool :propose_version_event, Proposal, :propose_version_event
    tool :propose_delete, Proposal, :propose_delete

    tool :withdraw_case_proposal, Proposal, :withdraw
    tool :list_case_comments, Comment, :list_for_case
    tool :create_case_comment, Comment, :post
  end

  graphql do
    queries do
      list Case, :list_cases, :list_cases
      get Case, :get_case, :read

      list Proposal, :list_case_proposals, :list_for_case
      list Proposal, :list_open_case_proposals, :list_open_for_case
      get Proposal, :get_case_proposal, :read

      list Comment, :list_case_comments, :list_for_case

      action Case, :render_case_preview, :render_preview
    end

    mutations do
      create Case, :open_case, :open
      update Case, :edit_case, :edit
      update Case, :request_case_review, :request_review
      update Case, :request_case_changes, :request_changes
      update Case, :approve_case, :approve
      update Case, :assign_case_cve_id, :assign_cve_id
      update Case, :publish_case, :publish
      update Case, :reopen_case, :reopen
      update Case, :close_case, :close
      update Case, :refresh_case_derivation, :refresh_derivation

      create CaseAssignment, :assign_case_user, :assign
      destroy CaseAssignment, :unassign_case_user, :unassign

      create AffectedPackage, :add_affected_package, :add
      create AffectedPackage, :add_otp_affected_package, :add_otp
      create AffectedPackage, :add_elixir_affected_package, :add_elixir
      create AffectedPackage, :add_gleam_affected_package, :add_gleam
      update AffectedPackage, :edit_affected_package, :edit
      destroy AffectedPackage, :remove_affected_package, :remove

      create PackageChannel, :add_package_channel, :add
      update PackageChannel, :edit_package_channel, :edit
      destroy PackageChannel, :remove_package_channel, :remove

      create VersionEvent, :add_version_event, :add
      update VersionEvent, :edit_version_event, :edit
      destroy VersionEvent, :remove_version_event, :remove

      create CaseReference, :add_case_reference, :add
      update CaseReference, :edit_case_reference, :edit
      destroy CaseReference, :remove_case_reference, :remove

      create CaseCredit, :add_case_credit, :add
      update CaseCredit, :edit_case_credit, :edit
      destroy CaseCredit, :remove_case_credit, :remove

      create CaseWeakness, :add_case_weakness, :add
      destroy CaseWeakness, :remove_case_weakness, :remove

      create CaseImpact, :add_case_impact, :add
      destroy CaseImpact, :remove_case_impact, :remove

      create Proposal, :propose_case_title, :propose_title
      create Proposal, :propose_case_description, :propose_description
      create Proposal, :propose_case_workarounds, :propose_workarounds
      create Proposal, :propose_case_configurations, :propose_configurations
      create Proposal, :propose_case_solutions, :propose_solutions
      create Proposal, :propose_case_discovery, :propose_discovery
      create Proposal, :propose_case_cvss, :propose_cvss
      create Proposal, :propose_case_date_public, :propose_date_public
      create Proposal, :propose_case_timeline, :propose_timeline
      create Proposal, :propose_case_cna_override, :propose_cna_override
      create Proposal, :propose_case_weakness, :propose_weakness
      create Proposal, :propose_case_impact, :propose_impact
      create Proposal, :propose_case_reference, :propose_reference
      create Proposal, :propose_case_credit, :propose_credit
      create Proposal, :propose_case_affected_package, :propose_affected_package
      create Proposal, :propose_case_otp_affected_package, :propose_otp_affected_package
      create Proposal, :propose_case_elixir_affected_package, :propose_elixir_affected_package
      create Proposal, :propose_case_gleam_affected_package, :propose_gleam_affected_package
      create Proposal, :propose_case_package_channel, :propose_package_channel
      create Proposal, :propose_case_version_event, :propose_version_event
      create Proposal, :propose_case_delete, :propose_delete
      update Proposal, :accept_case_proposal, :accept
      update Proposal, :decline_case_proposal, :decline
      update Proposal, :withdraw_case_proposal, :withdraw

      create Comment, :create_case_comment, :post
    end
  end

  paper_trail do
    include_versions? true
  end

  resources do
    resource Case do
      define :open_case, action: :open
      define :list_cases, action: :list_cases
      define :get_case, action: :read, get_by: [:id]
      define :edit_case, action: :edit
      define :request_case_review, action: :request_review
      define :request_case_changes, action: :request_changes
      define :approve_case, action: :approve
      define :assign_case_cve_id, action: :assign_cve_id
      define :publish_case, action: :publish
      define :mark_case_published, action: :mark_published
      define :reopen_case, action: :reopen
      define :close_case, action: :close
      define :render_case_preview, action: :render_preview
      define :refresh_case_derivation, action: :refresh_derivation
      define :apply_case_proposal, action: :apply_proposal
    end

    resource CaseAssignment do
      define :list_case_assignments, action: :read
      define :assign_case_user, action: :assign
      define :unassign_case_user, action: :unassign
    end

    resource AffectedPackage do
      define :list_affected_packages, action: :read
      define :get_affected_package, action: :read, get_by: [:id]
      define :add_affected_package, action: :add
      define :add_otp_affected_package, action: :add_otp
      define :add_elixir_affected_package, action: :add_elixir
      define :add_gleam_affected_package, action: :add_gleam
      define :edit_affected_package, action: :edit
      define :remove_affected_package, action: :remove
      define :store_affected_package_derivation, action: :store_derivation
      define :apply_affected_package_proposal, action: :apply_proposal
      define :apply_affected_package_proposal_insert, action: :apply_proposal_insert
      define :apply_affected_package_proposal_insert_otp, action: :apply_proposal_insert_otp
      define :apply_affected_package_proposal_insert_elixir, action: :apply_proposal_insert_elixir
      define :apply_affected_package_proposal_insert_gleam, action: :apply_proposal_insert_gleam
      define :apply_affected_package_proposal_delete, action: :apply_proposal_delete
    end

    resource PackageChannel do
      define :list_package_channels, action: :read
      define :get_package_channel, action: :read, get_by: [:id]
      define :add_package_channel, action: :add
      define :edit_package_channel, action: :edit
      define :remove_package_channel, action: :remove
      define :apply_package_channel_proposal, action: :apply_proposal
      define :apply_package_channel_proposal_insert, action: :apply_proposal_insert
      define :apply_package_channel_proposal_delete, action: :apply_proposal_delete
    end

    resource VersionEvent do
      define :list_version_events, action: :read
      define :add_version_event, action: :add
      define :edit_version_event, action: :edit
      define :remove_version_event, action: :remove
      define :apply_version_event_proposal, action: :apply_proposal
      define :apply_version_event_proposal_insert, action: :apply_proposal_insert
      define :apply_version_event_proposal_delete, action: :apply_proposal_delete
    end

    resource CaseReference do
      define :list_case_references, action: :read
      define :add_case_reference, action: :add
      define :edit_case_reference, action: :edit
      define :remove_case_reference, action: :remove
      define :apply_case_reference_proposal, action: :apply_proposal
      define :apply_case_reference_proposal_insert, action: :apply_proposal_insert
      define :apply_case_reference_proposal_delete, action: :apply_proposal_delete
    end

    resource CaseCredit do
      define :list_case_credits, action: :read
      define :add_case_credit, action: :add
      define :edit_case_credit, action: :edit
      define :remove_case_credit, action: :remove
      define :apply_case_credit_proposal, action: :apply_proposal
      define :apply_case_credit_proposal_insert, action: :apply_proposal_insert
      define :apply_case_credit_proposal_delete, action: :apply_proposal_delete
    end

    resource CaseWeakness do
      define :list_case_weaknesses, action: :read
      define :add_case_weakness, action: :add
      define :remove_case_weakness, action: :remove
      define :apply_case_weakness_proposal_insert, action: :apply_proposal_insert
      define :apply_case_weakness_proposal_delete, action: :apply_proposal_delete
    end

    resource CaseImpact do
      define :list_case_impacts, action: :read
      define :add_case_impact, action: :add
      define :remove_case_impact, action: :remove
      define :apply_case_impact_proposal_insert, action: :apply_proposal_insert
      define :apply_case_impact_proposal_delete, action: :apply_proposal_delete
    end

    resource Proposal do
      # Internal generic entry point (private action) for the LiveView's
      # projection-diff engine and tests; not exposed on MCP/GraphQL.
      define :create_case_proposal, action: :propose

      define :propose_title, action: :propose_title
      define :propose_description, action: :propose_description
      define :propose_workarounds, action: :propose_workarounds
      define :propose_configurations, action: :propose_configurations
      define :propose_solutions, action: :propose_solutions
      define :propose_discovery, action: :propose_discovery
      define :propose_cvss, action: :propose_cvss
      define :propose_date_public, action: :propose_date_public
      define :propose_timeline, action: :propose_timeline
      define :propose_cna_override, action: :propose_cna_override
      define :propose_weakness, action: :propose_weakness
      define :propose_impact, action: :propose_impact
      define :propose_reference, action: :propose_reference
      define :propose_credit, action: :propose_credit
      define :propose_affected_package, action: :propose_affected_package
      define :propose_otp_affected_package, action: :propose_otp_affected_package
      define :propose_elixir_affected_package, action: :propose_elixir_affected_package
      define :propose_gleam_affected_package, action: :propose_gleam_affected_package
      define :propose_package_channel, action: :propose_package_channel
      define :propose_version_event, action: :propose_version_event
      define :propose_delete, action: :propose_delete

      define :list_case_proposals, action: :list_for_case, args: [:case_id]
      define :list_open_case_proposals, action: :list_open_for_case, args: [:case_id]
      define :get_case_proposal, action: :read, get_by: [:id]
      define :accept_case_proposal, action: :accept
      define :decline_case_proposal, action: :decline
      define :withdraw_case_proposal, action: :withdraw
      define :supersede_case_proposal, action: :supersede
    end

    resource Comment do
      define :list_case_comments_all, action: :read
      define :post_case_comment, action: :post
      define :list_case_comments, action: :list_for_case, args: [:case_id]
    end
  end
end
