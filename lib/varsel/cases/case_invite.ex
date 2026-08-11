# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.CaseInvite do
  @moduledoc """
  A case assignment waiting for someone who has no account here yet.

  Named by a provider handle, and becomes a `Varsel.Cases.CaseAssignment` when
  an identity for that handle appears
  (`Varsel.Accounts.UserIdentity.Changes.ClaimCaseInvites`). It grants nothing
  until then.
  """

  use Ash.Resource,
    otp_app: :varsel,
    domain: Varsel.Cases,
    authorizers: [Ash.Policy.Authorizer],
    data_layer: AshPostgres.DataLayer,
    extensions: [AshPaperTrail.Resource],
    notifiers: [Ash.Notifier.PubSub]

  alias Varsel.Cases.Case
  alias Varsel.Cases.CaseInvite.Changes.CanonicalizeUsername
  alias Varsel.Cases.CaseInvite.Strategy

  postgres do
    table "case_invites"
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
    version_extensions extensions: [Varsel.Accounts.VersionActorReference]
  end

  actions do
    defaults [:read]

    create :invite do
      description "Invites someone to a case by their provider handle."
      primary? true
      accept [:case_id, :strategy, :username, :note]

      change CanonicalizeUsername
    end

    destroy :withdraw do
      description "Withdraws an invite that has not been claimed."
    end

    read :for_identity do
      description "Unclaimed invites naming a provider handle."

      argument :strategy, Strategy, allow_nil?: false
      argument :username, :ci_string, allow_nil?: false

      filter expr(strategy == ^arg(:strategy) and username == ^arg(:username))
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
    publish_all :destroy, [[:case_id]]
  end

  attributes do
    uuid_primary_key :id

    attribute :strategy, Strategy do
      description "The provider whose handle this invite names."
      allow_nil? false
      public? true
    end

    attribute :username, :ci_string do
      description "The handle at that provider, as the provider spells it."
      allow_nil? false
      public? true
    end

    attribute :note, :string do
      description "Why this person was invited (optional)."
      public? true
    end

    timestamps()
  end

  relationships do
    belongs_to :case, Case do
      allow_nil? false
      public? true
      attribute_writable? true
    end
  end

  identities do
    identity :unique_case_handle, [:case_id, :strategy, :username]
  end
end
