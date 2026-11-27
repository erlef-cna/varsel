# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Predisclosure.ListMember do
  @moduledoc """
  A case on a pre-disclosure list. Every subscriber of the list sees the case.
  """

  use Ash.Resource,
    otp_app: :varsel,
    domain: Varsel.Predisclosure,
    authorizers: [Ash.Policy.Authorizer],
    data_layer: AshPostgres.DataLayer,
    extensions: [AshPaperTrail.Resource],
    notifiers: [Ash.Notifier.PubSub]

  alias Varsel.Accounts.User
  alias Varsel.Cases.Case
  alias Varsel.Predisclosure.Changes.AnnounceSharedCases
  alias Varsel.Predisclosure.PredisclosureList

  postgres do
    table "predisclosure_list_members"
    repo Varsel.Repo

    references do
      reference :list, on_delete: :delete
      reference :case, on_delete: :delete
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

  # `:add` and `:remove` are reached only through `Varsel.Cases.Case`'s
  # `:predisclosure_lists` relationship, and their policy authorizes nothing
  # else.
  # credo:disable-for-next-line AshCredo.Check.Design.MissingCodeInterface
  actions do
    defaults [:read]

    create :add do
      description "Internal: puts a case on a pre-disclosure list. A case already on it stays as it is."
      primary? true
      accept [:list_id, :case_id]
      upsert? true
      upsert_identity :unique_list_case
      upsert_condition expr(false)
      return_skipped_upsert? true

      emit Varsel.Cases.Signals, :case_shared,
        dynamic?: true,
        description: "When the case was not on the list yet and the list has subscribers."

      change AnnounceSharedCases
    end

    destroy :remove do
      description "Internal: takes a case off a pre-disclosure list."
      primary? true
    end
  end

  policies do
    bypass AshOban.Checks.AshObanInteraction do
      authorize_if always()
    end

    # Lists are a POC's tool. Everyone else only gets the access they grant.
    policy action_type(:read) do
      access_type :strict
      authorize_if actor_attribute_equals(:role, :poc)
    end

    # Reached only through `Varsel.Cases.Case`'s `:set_predisclosure_lists`,
    # whose policy decides.
    policy action_type([:create, :destroy]) do
      authorize_if accessing_from(Case, :predisclosure_lists_join_assoc)
    end
  end

  pub_sub do
    module VarselWeb.Endpoint

    publish_all :create, ["case", :case_id]
    publish_all :destroy, ["case", :case_id]
    publish_all :create, ["predisclosure_list", :list_id]
    publish_all :destroy, ["predisclosure_list", :list_id]
    publish_all :create, ["predisclosure_list", "all"]
    publish_all :destroy, ["predisclosure_list", "all"]
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

    belongs_to :case, Case do
      allow_nil? false
      public? true
      attribute_writable? true
    end
  end

  identities do
    identity :unique_list_case, [:list_id, :case_id]
  end
end
