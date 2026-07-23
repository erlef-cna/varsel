# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.CaseImpact do
  @moduledoc """
  A CAPEC impact classification of the case, rendered into `impacts[]`.

  References the locally synced CAPEC catalog (`Varsel.CAPEC.AttackPattern`);
  the human-readable description ("CAPEC-66 SQL Injection") is derived from
  the catalog at render time.
  """

  use Ash.Resource,
    otp_app: :varsel,
    domain: Varsel.Cases,
    authorizers: [Ash.Policy.Authorizer],
    data_layer: AshPostgres.DataLayer,
    extensions: [AshPaperTrail.Resource, AshGraphql.Resource],
    notifiers: [Ash.Notifier.PubSub]

  alias Varsel.Cases.Changes.SupersedeOrphanedProposals
  alias Varsel.Cases.Checks.ActorAssignedToCase
  alias Varsel.Cases.Validations.CaseEditable

  graphql do
    type :case_impact
  end

  postgres do
    table "case_impacts"
    repo Varsel.Repo

    references do
      reference :case, on_delete: :delete
      reference :attack_pattern
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
      description "Classifies the case with a CAPEC attack pattern."
      primary? true
      accept [:case_id, :capec_id, :position]
      validate CaseEditable
    end

    destroy :remove do
      description "Removes a CAPEC classification."
      primary? true
      require_atomic? false
      validate CaseEditable
      change SupersedeOrphanedProposals
    end

    create :apply_proposal_insert do
      description "Internal: creates the row proposed by an accepted :insert proposal."
      accept [:case_id, :capec_id, :position]

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

    policy action_type([:create, :destroy]) do
      authorize_if actor_attribute_equals(:role, :poc)
      authorize_if ActorAssignedToCase
    end
  end

  pub_sub do
    module VarselWeb.Endpoint
    prefix "case"

    publish_all :create, [[:case_id]]
    publish_all :update, [[:case_id]]
    publish_all :destroy, [[:case_id]]
  end

  attributes do
    uuid_primary_key :id

    attribute :position, :integer do
      description "Order within impacts[]."
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

    belongs_to :attack_pattern, Varsel.CAPEC.AttackPattern do
      description "The CAPEC catalog entry (capec_id is the numeric CAPEC identifier)."
      allow_nil? false
      public? true
      attribute_type :integer
      source_attribute :capec_id
      destination_attribute :capec_id
      attribute_writable? true
    end
  end

  identities do
    identity :unique_case_capec, [:case_id, :capec_id]
  end
end
