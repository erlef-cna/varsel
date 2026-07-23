# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.CaseWeakness do
  @moduledoc """
  A CWE classification of the case, rendered into `problemTypes[]`.

  References the locally synced CWE catalog (`Varsel.CWE.Weakness`); the
  human-readable description ("CWE-79 Improper Neutralization of ...") is
  derived from the catalog at render time, so it can never drift.
  """

  use Ash.Resource,
    otp_app: :varsel,
    domain: Varsel.Cases,
    authorizers: [Ash.Policy.Authorizer],
    data_layer: AshPostgres.DataLayer,
    extensions: [AshPaperTrail.Resource, AshGraphql.Resource],
    notifiers: [Ash.Notifier.PubSub]

  alias Varsel.Cases.Changes.SupersedeOrphanedProposals
  alias Varsel.Cases.Validations.CaseEditable

  graphql do
    type :case_weakness
  end

  postgres do
    table "case_weaknesses"
    repo Varsel.Repo

    references do
      reference :case, on_delete: :delete
      reference :weakness
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
      description "Classifies the case with a CWE."
      primary? true
      accept [:case_id, :cwe_id, :position]
      validate CaseEditable
    end

    destroy :remove do
      description "Removes a CWE classification."
      primary? true
      require_atomic? false
      validate CaseEditable
      change SupersedeOrphanedProposals
    end

    create :apply_proposal_insert do
      description "Internal: creates the row proposed by an accepted :insert proposal."
      accept [:case_id, :cwe_id, :position]

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
    policy action_type([:read, :create, :destroy]) do
      authorize_if actor_attribute_equals(:role, :poc)
      authorize_if relates_to_actor_via([:case, :assignments, :user])
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
      description "Order within problemTypes[]."
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

    belongs_to :weakness, Varsel.CWE.Weakness do
      description "The CWE catalog entry (cwe_id is the numeric CWE identifier)."
      allow_nil? false
      public? true
      attribute_type :integer
      source_attribute :cwe_id
      destination_attribute :cwe_id
      attribute_writable? true
    end
  end

  identities do
    identity :unique_case_cwe, [:case_id, :cwe_id]
  end
end
