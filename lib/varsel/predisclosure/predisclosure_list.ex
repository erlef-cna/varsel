# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Predisclosure.PredisclosureList do
  @moduledoc """
  A named group of users who see the cases a POC shares with it.

  A subscriber of a list that holds a case may read the case, comment on it
  and propose changes, as an assigned user without a role may. A POC adds
  cases and subscribers by hand.
  """

  use Ash.Resource,
    otp_app: :varsel,
    domain: Varsel.Predisclosure,
    authorizers: [Ash.Policy.Authorizer],
    data_layer: AshPostgres.DataLayer,
    extensions: [AshPaperTrail.Resource, AshGraphql.Resource],
    notifiers: [Ash.Notifier.PubSub]

  alias Varsel.Accounts.User
  alias Varsel.Cases.Case
  alias Varsel.Predisclosure.ListMember
  alias Varsel.Predisclosure.ListSubscriber

  graphql do
    type :predisclosure_list
  end

  postgres do
    table "predisclosure_lists"
    repo Varsel.Repo
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

    read :list do
      description "Every pre-disclosure list the actor may see, by name."
      prepare build(sort: [name: :asc])
    end

    create :create do
      description "Creates a pre-disclosure list."
      primary? true
      accept [:name]
    end

    update :rename do
      description "Renames a pre-disclosure list."
      primary? true
      accept [:name]
    end

    destroy :destroy do
      description "Deletes a pre-disclosure list. Its subscribers lose access to the cases it held."
      primary? true
    end
  end

  policies do
    # Lists are a POC's tool. Everyone else only gets the access they grant.
    policy action_type([:read, :create, :update, :destroy]) do
      access_type :strict
      authorize_if actor_attribute_equals(:role, :poc)
    end
  end

  pub_sub do
    module VarselWeb.Endpoint
    prefix "predisclosure_list"

    publish_all :create, ["all"]
    publish_all :update, ["all"]
    publish_all :destroy, ["all"]
    publish_all :update, [[:id]]
  end

  attributes do
    uuid_primary_key :id

    attribute :name, :string do
      description "The name of the list, e.g. the group it stands for."
      allow_nil? false
      constraints max_length: 200
      public? true
    end

    timestamps()
  end

  relationships do
    has_many :subscribers, ListSubscriber do
      destination_attribute :list_id
      public? true
    end

    has_many :members, ListMember do
      destination_attribute :list_id
      public? true
    end

    many_to_many :cases, Case do
      through ListMember
      source_attribute_on_join_resource :list_id
      destination_attribute_on_join_resource :case_id
      public? true
    end

    many_to_many :users, User do
      through ListSubscriber
      source_attribute_on_join_resource :list_id
      destination_attribute_on_join_resource :user_id
      public? true
    end
  end

  aggregates do
    count :subscriber_count, :subscribers do
      description "How many users the list has."
      public? true
    end

    count :case_count, :members do
      description "How many cases the list holds."
      public? true
    end
  end

  identities do
    identity :unique_name, [:name]
  end
end
