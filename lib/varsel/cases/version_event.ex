# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.VersionEvent do
  @moduledoc """
  One vulnerability boundary *fact* for a logical product: where the
  vulnerability was introduced or fixed.

  The preferred fact is a `commit_sha`; `Varsel.Cases.Derivation` resolves it
  per distribution channel into version boundaries (tags containing the
  commit, OTP application versions, enumerated registry versions). An explicit
  `version` is used where commits don't apply — a date boundary on a hosted
  service, an OCI tag, or a release predating the repository. When both are
  set, `:git` channels use the commit and all other channels use the version.

  Multiple `:fixed` events represent backports: one fix boundary per release
  branch, rendered as `changes[]` chains in the CNA container. A fixed commit
  without any containing release tag is a first-class "fix not yet released"
  state — publish blocks on it unless the package sets `allow_unreleased_fix`
  or the channel overrides its versions.

  `package_channel_id` is nil for facts that apply to every channel of the
  package; set, it scopes the fact to one channel (e.g. date boundaries on a
  `:hosted` channel).
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
  alias Varsel.Cases.VersionEvent.Event
  alias Varsel.Cases.VersionEvent.Validations.ConsistentBoundary

  graphql do
    type :case_version_event
  end

  postgres do
    table "case_version_events"
    repo Varsel.Repo

    references do
      reference :case, on_delete: :delete
      reference :affected_package, on_delete: :delete
      reference :package_channel, on_delete: :delete
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
      description "Records a vulnerability boundary fact for a logical product."
      accept [:case_id, :affected_package_id, :package_channel_id | Proposable.fields(__MODULE__)]
      validate CaseEditable
      validate ConsistentBoundary
    end

    update :edit do
      description "Edits a boundary fact. Only allowed while the case is editable."
      accept Proposable.fields(__MODULE__)
      require_atomic? false
      validate CaseEditable
      validate ConsistentBoundary
    end

    destroy :remove do
      description "Removes a boundary fact."
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
      validate ConsistentBoundary
      change ApplyProposedField
    end

    create :apply_proposal_insert do
      description "Internal: creates the row proposed by an accepted :insert proposal."
      accept [:case_id, :affected_package_id, :package_channel_id | Proposable.fields(__MODULE__)]

      argument :proposal_id, :uuid, allow_nil?: false

      validate CaseEditable
      validate ConsistentBoundary
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

  attributes do
    uuid_primary_key :id

    attribute :event, Event do
      allow_nil? false
      public? true
    end

    attribute :commit_sha, :string do
      description "Full 40-character commit SHA of the boundary commit."
      constraints match: ~r/^[0-9a-f]{40}$/
      public? true
    end

    attribute :version, :string do
      description "Explicit version boundary for channels where commits don't apply."
      public? true
    end

    attribute :note, :string do
      description "Context for reviewers (which release branch, why this boundary)."
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

    belongs_to :affected_package, Varsel.Cases.AffectedPackage do
      allow_nil? false
      public? true
      attribute_writable? true
    end

    belongs_to :package_channel, Varsel.Cases.PackageChannel do
      description "Scopes the fact to one channel; nil applies to all channels."
      public? true
      attribute_writable? true
    end
  end
end
