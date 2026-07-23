# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.CaseCredit do
  @moduledoc """
  One credited person or organization, rendered into `credits[]`.

  Renders as `{lang: "en", type, value}` where value is the person's real name
  followed by ` / <organization>` when an organization is set (EEF convention,
  e.g. "Jonatan Männchen / EEF").
  """

  use Ash.Resource,
    otp_app: :varsel,
    domain: Varsel.Cases,
    authorizers: [Ash.Policy.Authorizer],
    data_layer: AshPostgres.DataLayer,
    extensions: [AshPaperTrail.Resource, AshGraphql.Resource],
    notifiers: [Ash.Notifier.PubSub]

  alias Varsel.Accounts.User
  alias Varsel.Cases.CaseCredit.CreditType
  alias Varsel.Cases.Changes.ApplyProposedField
  alias Varsel.Cases.Changes.SupersedeOrphanedProposals
  alias Varsel.Cases.Checks.ActorAssignedToCase
  alias Varsel.Cases.Proposable
  alias Varsel.Cases.Validations.CaseEditable

  graphql do
    type :case_credit
  end

  postgres do
    table "case_credits"
    repo Varsel.Repo

    references do
      reference :case, on_delete: :delete
      reference :user, on_delete: :nilify
    end
  end

  paper_trail do
    change_tracking_mode :changes_only
    reference_source? false
    ignore_attributes [:inserted_at, :updated_at]
    only_when_changed? true
    store_action_name? true
    belongs_to_actor :user, User, domain: Varsel.Accounts
  end

  actions do
    defaults [:read]

    create :add do
      description "Adds a credit to a case."
      primary? true
      accept [:case_id, :user_id | Proposable.fields(__MODULE__)]
      validate CaseEditable
    end

    update :edit do
      description "Edits a credit. Only allowed while the case is editable."
      primary? true
      accept [:user_id | Proposable.fields(__MODULE__)]
      require_atomic? false
      validate CaseEditable
    end

    destroy :remove do
      description "Removes a credit from a case."
      primary? true
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

  pub_sub do
    module VarselWeb.Endpoint
    prefix "case"

    publish_all :create, [[:case_id]]
    publish_all :update, [[:case_id]]
    publish_all :destroy, [[:case_id]]
  end

  attributes do
    uuid_primary_key :id

    attribute :name, :string do
      description "The credited person's real name (or tool/organization name)."
      allow_nil? false
      public? true
    end

    attribute :organization, :string do
      description "Optional affiliation, appended as \" / <organization>\"."
      public? true
    end

    attribute :credit_type, CreditType do
      allow_nil? false
      default :finder
      public? true
    end

    attribute :position, :integer do
      description "Order within credits[]."
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

    belongs_to :user, User do
      description "The credited person's account, when known."
      allow_nil? true
      public? true
      attribute_writable? true
    end
  end
end
