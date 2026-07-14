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
    tool :create_case_proposal, Proposal, :propose
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

      create Proposal, :create_case_proposal, :propose
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
      define :reopen_case, action: :reopen
      define :close_case, action: :close
      define :render_case_preview, action: :render_preview
      define :refresh_case_derivation, action: :refresh_derivation
    end

    resource CaseAssignment do
      define :assign_case_user, action: :assign
      define :unassign_case_user, action: :unassign
    end

    resource AffectedPackage do
      define :add_affected_package, action: :add
      define :edit_affected_package, action: :edit
      define :remove_affected_package, action: :remove
    end

    resource PackageChannel do
      define :add_package_channel, action: :add
      define :edit_package_channel, action: :edit
      define :remove_package_channel, action: :remove
    end

    resource VersionEvent do
      define :add_version_event, action: :add
      define :edit_version_event, action: :edit
      define :remove_version_event, action: :remove
    end

    resource CaseReference do
      define :add_case_reference, action: :add
      define :edit_case_reference, action: :edit
      define :remove_case_reference, action: :remove
    end

    resource CaseCredit do
      define :add_case_credit, action: :add
      define :edit_case_credit, action: :edit
      define :remove_case_credit, action: :remove
    end

    resource CaseWeakness do
      define :add_case_weakness, action: :add
      define :remove_case_weakness, action: :remove
    end

    resource CaseImpact do
      define :add_case_impact, action: :add
      define :remove_case_impact, action: :remove
    end

    resource Proposal do
      define :create_case_proposal, action: :propose
      define :list_case_proposals, action: :list_for_case, args: [:case_id]
      define :list_open_case_proposals, action: :list_open_for_case, args: [:case_id]
      define :get_case_proposal, action: :read, get_by: [:id]
      define :accept_case_proposal, action: :accept
      define :decline_case_proposal, action: :decline
      define :withdraw_case_proposal, action: :withdraw
    end

    resource Comment do
      define :post_case_comment, action: :post
      define :list_case_comments, action: :list_for_case, args: [:case_id]
    end
  end
end
