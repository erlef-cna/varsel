# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.CaseAssignment do
  @moduledoc """
  Grants a user (typically a `:supporter`) access to one specific case.

  Assignments are the only path by which non-POC users see and work on cases;
  every policy in the Cases domain checks them. POCs manage assignments and
  have full access regardless.
  """

  use Ash.Resource,
    otp_app: :varsel,
    domain: Varsel.Cases,
    authorizers: [Ash.Policy.Authorizer],
    data_layer: AshPostgres.DataLayer,
    extensions: [AshPaperTrail.Resource, AshGraphql.Resource],
    notifiers: [Ash.Notifier.PubSub]

  alias Varsel.Accounts.User

  graphql do
    type :case_assignment
  end

  postgres do
    table "case_assignments"
    repo Varsel.Repo

    references do
      reference :case, on_delete: :delete
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
  end

  actions do
    defaults [:read]

    create :assign do
      description "POC grants a user access to a case."
      accept [:case_id, :user_id, :note]
    end

    destroy :unassign do
      description "POC revokes a user's access to a case."
    end
  end

  policies do
    # Assigned users may see who else works the case; POCs see everything.
    policy action_type(:read) do
      authorize_if actor_attribute_equals(:role, :poc)
      authorize_if relates_to_actor_via([:case, :assignments, :user])
    end

    policy action_type([:create, :destroy]) do
      authorize_if actor_attribute_equals(:role, :poc)
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

    attribute :note, :string do
      description "Why this user was assigned (optional)."
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
      allow_nil? false
      public? true
      attribute_writable? true
    end
  end

  identities do
    identity :unique_case_user, [:case_id, :user_id]
  end
end
