# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.CaseReference do
  @moduledoc """
  One stored reference of a case, rendered into `references[]`.

  Only non-derivable references are stored: the vendor advisory (GHSA), extra
  advisories, version-scheme explainers, and so on. The `cna.erlef.org` /
  `osv.dev` self-links and patch-commit links (repo + fixed commit SHA) are
  appended at render time — stored rows win over derived ones on URL conflict.

  Ordering is meaningful (the vendor advisory comes first); `position` sorts
  the stored rows ahead of derived ones.
  """

  use Ash.Resource,
    otp_app: :varsel,
    domain: Varsel.Cases,
    authorizers: [Ash.Policy.Authorizer],
    data_layer: AshPostgres.DataLayer,
    extensions: [AshPaperTrail.Resource, AshGraphql.Resource]

  alias Varsel.Cases.Changes.ApplyProposedField
  alias Varsel.Cases.Changes.SupersedeOrphanedProposals
  alias Varsel.Cases.Checks.ActorAssignedToCase
  alias Varsel.Cases.Proposable
  alias Varsel.Cases.Validations.CaseEditable

  # CVE 5.2 reference-tag vocabulary (tags/reference-tags.json), plus x_ custom tags.
  @reference_tags ~w(
    broken-link customer-entitlement exploit government-resource issue-tracking
    mailing-list mitigation not-applicable patch permissions-required
    media-coverage product related release-notes signature technical-description
    third-party-advisory vendor-advisory vdb-entry
  )

  graphql do
    type :case_reference
  end

  postgres do
    table "case_references"
    repo Varsel.Repo

    references do
      reference :case, on_delete: :delete
    end
  end

  paper_trail do
    change_tracking_mode :changes_only
    reference_source? false
    ignore_attributes [:inserted_at, :updated_at]
    only_when_changed? true
    store_action_name? true
    belongs_to_actor :user, Varsel.Accounts.User, domain: Varsel.Accounts
  end

  actions do
    defaults [:read]

    create :add do
      description "Adds a reference to a case."
      accept [:case_id | Proposable.fields(__MODULE__)]
      validate CaseEditable
    end

    update :edit do
      description "Edits a reference. Only allowed while the case is editable."
      accept Proposable.fields(__MODULE__)
      require_atomic? false
      validate CaseEditable
    end

    destroy :remove do
      description "Removes a reference from a case."
      require_atomic? false
      validate CaseEditable
      change SupersedeOrphanedProposals
    end

    update :apply_proposal do
      description "Internal: applies one accepted proposal value to a single field."
      accept []
      require_atomic? false

      argument :field, :string, allow_nil?: false
      argument :value, :term
      argument :proposal_id, :uuid, allow_nil?: false

      validate CaseEditable
      change ApplyProposedField
    end

    create :apply_proposal_insert do
      description "Internal: creates the row proposed by an accepted :insert proposal."
      accept [:case_id | Proposable.fields(__MODULE__)]

      argument :proposal_id, :uuid, allow_nil?: false

      validate CaseEditable
    end

    destroy :apply_proposal_delete do
      description "Internal: removes the row targeted by an accepted :delete proposal."
      require_atomic? false

      argument :proposal_id, :uuid, allow_nil?: false

      validate CaseEditable
      change SupersedeOrphanedProposals
    end
  end

  policies do
    policy action_type(:read) do
      authorize_if actor_attribute_equals(:role, :poc)
      authorize_if expr(exists(case.assignments, user_id == ^actor(:id)))
    end

    policy action_type([:create, :update, :destroy]) do
      authorize_if actor_attribute_equals(:role, :poc)
      authorize_if ActorAssignedToCase
    end
  end

  validations do
    validate {Varsel.Cases.CaseReference.Validations.ValidTags, allowed: @reference_tags} do
      where action_is([:add, :edit, :apply_proposal, :apply_proposal_insert])
    end
  end

  attributes do
    uuid_primary_key :id

    attribute :url, :string do
      allow_nil? false
      public? true
    end

    attribute :tags, {:array, :string} do
      description "CVE 5.2 reference tags (e.g. vendor-advisory, patch) or x_-prefixed custom tags."
      allow_nil? false
      default []
      public? true
    end

    attribute :position, :integer do
      description "Order within references[] (the vendor advisory comes first)."
      allow_nil? false
      default 0
      public? true
    end

    timestamps()
  end

  relationships do
    belongs_to :case, Varsel.Cases.Case do
      allow_nil? false
      public? true
      attribute_writable? true
    end
  end

  identities do
    identity :unique_case_url, [:case_id, :url]
  end
end
