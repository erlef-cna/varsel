# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.CaseAssignment do
  @moduledoc """
  Grants a user access to one specific case.

  Assignments are the only path by which non-POC users see and work on cases;
  every policy in the Cases domain checks them. What that access amounts to
  depends on the user's role — a supporter edits, an unroled collaborator
  reads and proposes. POCs have full access regardless.
  """

  use Ash.Resource,
    otp_app: :varsel,
    domain: Varsel.Cases,
    authorizers: [Ash.Policy.Authorizer],
    data_layer: AshPostgres.DataLayer,
    extensions: [AshPaperTrail.Resource, AshGraphql.Resource],
    notifiers: [Varsel.Notifications.Notifier, Ash.Notifier.PubSub]

  alias Varsel.Accounts.Signals
  alias Varsel.Accounts.User
  alias Varsel.Cases.Case
  alias Varsel.Cases.CaseAssignment.Changes.ClaimInvites

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
    version_extensions extensions: [Varsel.Accounts.VersionActorReference]
  end

  # `:claim_invites` is reached only by the `:identity_linked` listener, and
  # its policy authorizes nothing else.
  # credo:disable-for-next-line AshCredo.Check.Design.MissingCodeInterface
  actions do
    defaults [:read]

    create :assign do
      description "Grants a user access to a case. A user who has access keeps the assignment they have."
      primary? true
      accept [:case_id, :user_id, :note]
      upsert? true
      upsert_identity :unique_case_user
      upsert_condition expr(false)
      return_skipped_upsert? true
    end

    destroy :unassign do
      description "POC revokes a user's access to a case."
    end

    action :claim_invites do
      description "Internal: turns the invites naming a freshly linked handle into assignments."

      argument :signal, Varsel.Accounts.Signals.IdentityLinked, allow_nil?: false

      run ClaimInvites
    end
  end

  policies do
    bypass AshOban.Checks.AshObanInteraction do
      authorize_if always()
    end

    # Assigned users may see who else works the case; POCs see everything.
    policy action_type(:read) do
      authorize_if actor_attribute_equals(:role, :poc)
      authorize_if relates_to_actor_via([:case, :assignments, :user])
    end

    # The invite claim runs as the user who just signed in. Their invite is
    # what granted them the case, so the signal is the permission.
    policy action(:claim_invites) do
      authorize_if signal_in(Signals, :identity_linked)
    end

    # A supporter reaches this only through `Varsel.Cases.Case`'s
    # `:grant_access`, whose own policy decides on the case row that they work
    # it. Asking here instead would be a filter check on a create, which the
    # row being inserted answers.
    policy action_type(:create) do
      authorize_if signal_in(Signals, :identity_linked)
      authorize_if actor_attribute_equals(:role, :poc)
      authorize_if accessing_from(Case, :assignments)
      authorize_if context_equals([:private, :granting_case_access?], true)
    end

    policy action_type(:destroy) do
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
    belongs_to :case, Case do
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

  signals_in do
    from Signals do
      on :identity_linked, :claim_invites
    end
  end

  identities do
    identity :unique_case_user, [:case_id, :user_id]
  end
end
