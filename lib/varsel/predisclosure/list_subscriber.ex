# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Predisclosure.ListSubscriber do
  @moduledoc """
  A user on a pre-disclosure list. The user sees every case the list holds.
  """

  use Ash.Resource,
    otp_app: :varsel,
    domain: Varsel.Predisclosure,
    authorizers: [Ash.Policy.Authorizer],
    data_layer: AshPostgres.DataLayer,
    extensions: [AshPaperTrail.Resource, AshGraphql.Resource],
    notifiers: [Ash.Notifier.PubSub]

  alias Varsel.Accounts.User
  alias Varsel.Predisclosure.Changes.AnnounceSharedCases
  alias Varsel.Predisclosure.PredisclosureList

  graphql do
    type :predisclosure_list_subscriber
  end

  postgres do
    table "predisclosure_list_subscribers"
    repo Varsel.Repo

    references do
      reference :list, on_delete: :delete
      reference :user, on_delete: :delete
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

    create :subscribe do
      description "Puts a user on a pre-disclosure list. A user already on it stays as they are."
      primary? true
      accept [:list_id, :user_id]
      upsert? true
      upsert_identity :unique_list_user
      upsert_condition expr(false)
      return_skipped_upsert? true

      emit Varsel.Cases.Signals, :case_shared,
        dynamic?: true,
        description: "Once per case the list holds, when the user was not on the list yet."

      change AnnounceSharedCases
    end

    destroy :unsubscribe do
      description "Takes a user off a pre-disclosure list."
      primary? true
    end
  end

  policies do
    bypass AshOban.Checks.AshObanInteraction do
      authorize_if always()
    end

    # Lists are a POC's tool. Everyone else only gets the access they grant.
    policy action_type([:read, :create, :destroy]) do
      access_type :strict
      authorize_if actor_attribute_equals(:role, :poc)
    end
  end

  pub_sub do
    module VarselWeb.Endpoint
    prefix "predisclosure_list"

    publish_all :create, [[:list_id]]
    publish_all :destroy, [[:list_id]]
    publish_all :create, ["all"]
    publish_all :destroy, ["all"]
  end

  attributes do
    uuid_primary_key :id
    timestamps()
  end

  relationships do
    belongs_to :list, PredisclosureList do
      allow_nil? false
      public? true
      attribute_writable? true
    end

    belongs_to :user, User do
      allow_nil? false
      public? true
      attribute_writable? true
    end
  end

  identities do
    identity :unique_list_user, [:list_id, :user_id]
  end
end
