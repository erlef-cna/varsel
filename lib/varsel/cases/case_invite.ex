# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

# credo:disable-for-this-file AshCredo.Check.Design.MissingIdentity
# `email` is deliberately non-unique: one person is invited to every case that
# names them, and uniqueness lives on `unique_case_handle`.
defmodule Varsel.Cases.CaseInvite do
  @moduledoc """
  A case assignment waiting for someone who has no account here yet.

  Named by a provider handle, and becomes a `Varsel.Cases.CaseAssignment` when
  an identity for that handle appears
  (`Varsel.Accounts.UserIdentity.Changes.ClaimCaseInvites`). It grants nothing
  until then.

  The person is told once, by email, at the address their provider reports.
  The email carries no case content, only a sign-in link. The address is a
  POC-only field and leaves with the invite.
  """

  use Ash.Resource,
    otp_app: :varsel,
    domain: Varsel.Cases,
    authorizers: [Ash.Policy.Authorizer],
    data_layer: AshPostgres.DataLayer,
    extensions: [AshPaperTrail.Resource, AshOban],
    notifiers: [Ash.Notifier.PubSub]

  alias AshOban.Checks.AshObanInteraction
  alias Varsel.Cases.Case
  alias Varsel.Cases.CaseInvite.Changes.ResolveContact
  alias Varsel.Cases.CaseInvite.EmailStatus
  alias Varsel.Cases.CaseInvite.Strategy
  alias Varsel.Notifications.Emails

  postgres do
    table "case_invites"
    repo Varsel.Repo

    references do
      reference :case, on_delete: :delete
    end
  end

  field_policies do
    field_policy_bypass :*, AshObanInteraction do
      authorize_if always()
    end

    # The address is personal data about someone who has no account here.
    field_policy :email do
      authorize_if actor_attribute_equals(:role, :poc)
    end

    field_policy :* do
      authorize_if always()
    end
  end

  paper_trail do
    change_tracking_mode :changes_only
    reference_source? false
    ignore_attributes [:inserted_at, :updated_at, :email]
    only_when_changed? true
    store_action_name? true
    belongs_to_actor :user, Varsel.Accounts.User, domain: Varsel.Accounts
    version_extensions extensions: [Varsel.Accounts.VersionActorReference]
  end

  oban do
    triggers do
      trigger :email do
        action :send_email
        where expr(email_status == :pending)
        worker_module_name Varsel.Cases.CaseInvite.EmailWorker
        scheduler_module_name Varsel.Cases.CaseInvite.EmailScheduler
        queue :default
        max_attempts 3
        scheduler_cron "*/15 * * * *"
        worker_opts unique: [period: :infinity, states: :incomplete, keys: [:primary_key]]
      end
    end
  end

  actions do
    defaults [:read]

    create :invite do
      description "Invites someone to a case by their provider handle, and queues their invite email."
      primary? true
      accept [:case_id, :strategy, :username, :note]

      argument :email, :string do
        description "The address to email when the provider lists none for the account."
      end

      argument :skip_email, :boolean do
        default false

        description "Send no invite email. Accepted only when the provider lists no address for the account."
      end

      change ResolveContact
      change run_oban_trigger(:email)
    end

    destroy :withdraw do
      description "Withdraws an invite that has not been claimed."
    end

    update :send_email do
      description "Oban worker action: sends the invite email for this row."
      accept []
      require_atomic? false

      change set_attribute(:email_status, :sent)
      change set_attribute(:emailed_at, &DateTime.utc_now/0)

      change after_action(fn _changeset, invite, _context ->
               Emails.deliver_invite(invite)
               {:ok, invite}
             end)
    end

    read :for_identity do
      description "Unclaimed invites naming a provider handle."

      argument :strategy, Strategy, allow_nil?: false
      argument :username, :ci_string, allow_nil?: false

      filter expr(strategy == ^arg(:strategy) and username == ^arg(:username))
    end
  end

  policies do
    # The worker re-check reads with no actor; as a plain policy the
    # relationship filter below would narrow it to nothing.
    bypass action_type(:read) do
      access_type :strict
      authorize_if AshObanInteraction
    end

    policy action_type([:read, :destroy]) do
      authorize_if actor_attribute_equals(:system, :identity_claim)
      authorize_if actor_attribute_equals(:role, :poc)
      authorize_if relates_to_actor_via([:case, :assignments, :user])
    end

    # Inviting stays with people.
    policy action_type(:create) do
      authorize_if actor_attribute_equals(:role, :poc)
      authorize_if relates_to_actor_via([:case, :assignments, :user])
    end

    policy action(:send_email) do
      access_type :strict
      authorize_if AshObanInteraction
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

    attribute :email, :ci_string do
      description "The address the invite email goes to, when there is one."
      public? true
      sensitive? true
    end

    attribute :email_status, EmailStatus do
      description "What became of the invite email."
      allow_nil? false
      public? true
    end

    attribute :emailed_at, :utc_datetime_usec do
      description "When the invite email went out; nil until then."
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
