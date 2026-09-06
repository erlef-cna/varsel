# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.CaseCredit do
  @moduledoc """
  One credited person or organization, rendered into `credits[]`.

  Renders as `{lang: "en", type, value}` where value is the person's real name
  followed by ` / <organization>` when an organization is set (EEF convention,
  e.g. "Jonatan Männchen / EEF").

  A credit names the person by their provider handles, and links to their
  account when one holds a handle, at creation or when they later sign in.
  The account contributes the name and organization the person asked to be
  credited as (`Varsel.Cases.CaseCredit.Changes.ResolveCreditedUser`).
  """

  use Ash.Resource,
    otp_app: :varsel,
    domain: Varsel.Cases,
    authorizers: [Ash.Policy.Authorizer],
    data_layer: AshPostgres.DataLayer,
    extensions: [AshPaperTrail.Resource, AshGraphql.Resource],
    notifiers: [Ash.Notifier.PubSub]

  alias Varsel.Accounts.User
  alias Varsel.Cases.CaseCredit.Changes.ResolveCreditedUser
  alias Varsel.Cases.CaseCredit.CreditType
  alias Varsel.Cases.CaseCredit.Handle
  alias Varsel.Cases.Changes.ApplyProposedField
  alias Varsel.Cases.Changes.SupersedeOrphanedProposals
  alias Varsel.Cases.Proposable

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
    version_extensions extensions: [Varsel.Accounts.VersionActorReference]
  end

  actions do
    defaults [:read]

    create :add do
      description """
      Adds a credit to a case. The name may be left out when a handle or
      `user_id` names an account: the credit then takes the name the account
      asked to be credited as.
      """

      primary? true
      accept [:case_id, :user_id | Proposable.fields(__MODULE__)]
      allow_nil_input [:name]
      change {ResolveCreditedUser, mode: :fill}
    end

    update :edit do
      description "Edits a credit. Only allowed while the case is editable."
      primary? true
      accept [:user_id | Proposable.fields(__MODULE__)]
      require_atomic? false
      change {ResolveCreditedUser, mode: :fill}
    end

    update :refresh do
      description """
      Copies the credited account's current name and organization again, or,
      for a credit with no account, the name its provider now lists for the
      handle.
      """

      accept []
      require_atomic? false
      change {ResolveCreditedUser, mode: :overwrite}
    end

    update :claim do
      description "Internal: links a credit to the account that signed in with one of its handles."
      public? false
      accept [:user_id]
      require_atomic? false
    end

    read :for_identity do
      description "Internal: unlinked credits naming a provider handle, for the sign-in claim."
      public? false

      argument :strategy, :string, allow_nil?: false
      argument :username, :string, allow_nil?: false

      filter expr(
               is_nil(user_id) and
                 fragment(
                   "EXISTS (SELECT 1 FROM unnest(?) AS h WHERE h->>'strategy' = ? AND lower(h->>'username') = lower(?))",
                   handles,
                   ^arg(:strategy),
                   ^arg(:username)
                 )
             )
    end

    destroy :remove do
      description "Removes a credit from a case."
      primary? true
      require_atomic? false
      change SupersedeOrphanedProposals
    end

    update :apply_proposal do
      description "Internal: applies one accepted proposal value to a single field."
      accept []
      require_atomic? false

      argument :field, :string, allow_nil?: false
      argument :value, :term
      argument :proposal_id, :uuid, allow_nil?: false
      change ApplyProposedField
      change {ResolveCreditedUser, mode: :fill}
    end

    create :apply_proposal_insert do
      description "Internal: creates the row proposed by an accepted :insert proposal."
      accept [:case_id | Proposable.fields(__MODULE__)]

      argument :proposal_id, :uuid, allow_nil?: false
      change {ResolveCreditedUser, mode: :fill}
    end

    destroy :apply_proposal_delete do
      description "Internal: removes the row targeted by an accepted :delete proposal."
      require_atomic? false

      argument :proposal_id, :uuid, allow_nil?: false
      change SupersedeOrphanedProposals
    end
  end

  policies do
    # Linking an account changes nothing the record publishes, so a sign-in
    # claims a credit whatever state its case is in.
    bypass action(:claim) do
      authorize_if actor_attribute_equals(:system, :identity_claim)
    end

    policy action_type(:read) do
      authorize_if actor_attribute_equals(:system, :identity_claim)
      authorize_if actor_attribute_equals(:role, :poc)
      authorize_if relates_to_actor_via([:case, :assignments, :user])
    end

    # Writing a case's facts is editing the case, so it needs a role as
    # well as an assignment — an assigned collaborator proposes instead.
    policy action_type([:create, :update, :destroy]) do
      authorize_if actor_attribute_equals(:role, :poc)

      authorize_if expr(
                     ^actor(:role) == :supporter and
                       exists(case.assignments, user_id == ^actor(:id))
                   )
    end

    # Content freeze: child rows may only change while the parent case is editable.
    policy action_type([:create, :update, :destroy]) do
      authorize_if expr(case.state in [:draft, :review])
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

    attribute :handles, {:array, Handle} do
      description "The provider accounts the person goes by, one per provider."
      allow_nil? false
      default []
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
