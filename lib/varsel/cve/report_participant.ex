# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

# credo:disable-for-this-file AshCredo.Check.Design.MissingIdentity
# `email` is deliberately non-unique: the same person is a participant on every
# report that names them, and uniqueness lives on `unique_report_handle`.
defmodule Varsel.CVE.ReportParticipant do
  @moduledoc """
  Someone an upstream intake named on a report: its reporter, or a maintainer
  of the reported package.

  A participant is a claim by the sending system about a person, not an account
  here and not a grant of access. `user_id` is stamped if and when a matching
  identity signs in.

  Rows are transient: opening a case from the report consumes them into case
  assignments and invites, and the report keeps only its reporter link.
  """

  use Ash.Resource,
    otp_app: :varsel,
    domain: Varsel.CVE,
    authorizers: [Ash.Policy.Authorizer],
    data_layer: AshPostgres.DataLayer,
    extensions: [AshPaperTrail.Resource]

  alias Varsel.Accounts.User
  alias Varsel.Cases.CaseInvite.Strategy
  alias Varsel.CVE.ReportParticipant.Role
  alias Varsel.CVE.VulnerabilityReport

  postgres do
    table "report_participants"
    repo Varsel.Repo

    references do
      reference :report, on_delete: :delete
      reference :user, on_delete: :nilify
    end
  end

  paper_trail do
    change_tracking_mode :changes_only
    reference_source? false
    ignore_attributes [:inserted_at, :updated_at, :email]
    only_when_changed? true
    store_action_name? true
    belongs_to_actor :user, User, domain: Varsel.Accounts
    version_extensions extensions: [Varsel.Accounts.VersionActorReference]
  end

  actions do
    defaults [:read]

    create :record do
      description "Records someone an intake named on a report."
      primary? true
      accept [:report_id, :role, :strategy, :username, :name, :email]

      change Varsel.CVE.ReportParticipant.Changes.LinkKnownAccount
    end

    read :for_identity do
      description "Unclaimed participants naming a provider handle."

      argument :strategy, Strategy, allow_nil?: false
      argument :username, :ci_string, allow_nil?: false

      filter expr(strategy == ^arg(:strategy) and username == ^arg(:username) and is_nil(user_id))
    end

    update :link_user do
      description "Points a participant at the account that proved it owns the handle."
      accept [:user_id]
      require_atomic? false
    end

    destroy :spend do
      description """
      Drops a participant the CNA no longer needs.

      These rows hold personal data about people who never signed up here, so
      we keep as little of it as processing a report and its case requires,
      and no longer. When a process ends — the report becomes a case, or is
      rejected — everything it no longer needs goes.

      Anyone who registered an account in the meantime keeps their details
      under their own control, where they can delete them themselves.
      """

      primary? true
    end
  end

  policies do
    # Participant rows describe third parties who never asked to be here: a
    # package's maintainers, and a reporter's contact details. No person but a
    # POC reads them on any surface. The reporter reads their own report
    # instead, which carries no participant data.
    # Written only by the intake the sending system is authenticated for. A
    # reporter naming their own maintainers would be writing the record that
    # later grants case access.
    policy action_type(:create) do
      authorize_if actor_attribute_equals(:system, :hexpm_intake)
      authorize_if actor_attribute_equals(:role, :poc)
    end

    policy action_type([:read, :update, :destroy]) do
      authorize_if actor_attribute_equals(:system, :identity_claim)
      authorize_if actor_attribute_equals(:role, :poc)
    end
  end

  attributes do
    uuid_primary_key :id

    attribute :role, Role do
      description "Whether this person reported the issue or maintains the package."
      allow_nil? false
      public? true
    end

    attribute :strategy, Strategy do
      description "The provider whose handle names this person."
      allow_nil? false
      public? true
    end

    attribute :username, :ci_string do
      description "The handle at that provider, as the provider spells it."
      allow_nil? false
      public? true
    end

    attribute :name, :string do
      description "Display name as the sending system knows it."
      public? true
    end

    attribute :email, :string do
      description "Address the sending system holds for this person."
      public? true
      sensitive? true
    end

    timestamps()
  end

  relationships do
    belongs_to :report, VulnerabilityReport do
      allow_nil? false
      public? true
      attribute_writable? true
    end

    belongs_to :user, User do
      description "The account that proved it owns the handle, once one signs in."
      allow_nil? true
      public? true
      attribute_writable? true
    end
  end

  identities do
    identity :unique_report_handle, [:report_id, :role, :strategy, :username]
  end
end
