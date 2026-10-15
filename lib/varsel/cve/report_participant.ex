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
    extensions: [AshPaperTrail.Resource],
    notifiers: [Ash.Notifier.PubSub]

  alias Varsel.Accounts.User
  alias Varsel.Cases.CaseInvite.Strategy
  alias Varsel.CVE.ReportParticipant.Changes.ClaimForIdentity
  alias Varsel.CVE.ReportParticipant.Role
  alias Varsel.CVE.Signals
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
    ignore_attributes [:inserted_at, :updated_at, :name, :email]
    only_when_changed? true
    store_action_name? true
    belongs_to_actor :user, User, domain: Varsel.Accounts
    version_extensions extensions: [Varsel.Accounts.VersionActorReference]
  end

  # Both updates are single-purpose system writes (the sign-in link and hex.pm's
  # erasure), so neither is a default update to fall back on.
  #
  # `:for_report` selects the rows the `:report_resolved` listener spends, and
  # nothing else reads it.
  # credo:disable-for-next-line /AshCredo.Check.Design.Missing(PrimaryAction|CodeInterface)/
  actions do
    defaults [:read]

    create :record do
      description "Records someone an intake named on a report."
      primary? true
      accept [:report_id, :role, :strategy, :username, :name, :email]

      change Varsel.CVE.ReportParticipant.Changes.LinkKnownAccount
    end

    read :for_identity do
      description "Internal: unclaimed participants naming a provider handle, for the sign-in claim."
      public? false

      argument :strategy, Strategy, allow_nil?: false
      argument :username, :ci_string, allow_nil?: false

      filter expr(strategy == ^arg(:strategy) and username == ^arg(:username) and is_nil(user_id))
    end

    read :for_report do
      description "Internal: the participants a report still holds, for the spend on resolution."
      public? false

      argument :report_id, :uuid, allow_nil?: false

      filter expr(report_id == ^arg(:report_id))

      pagination keyset?: true, required?: false
    end

    action :claim_for_identity do
      description "Internal: points the participants naming a freshly vouched-for handle at the account."

      argument :signal, Varsel.Accounts.Signals.IdentityLinked, allow_nil?: false

      run ClaimForIdentity
    end

    update :erase_hex_person do
      description """
      Applies hex.pm's notice that it erased an account (GDPR Article 19):
      clears the name and address on every participant it named by that
      username or address. The handle and role stay.
      """

      accept []

      argument :username, :ci_string, allow_nil?: false
      argument :email, :string

      change filter(
               expr(
                 strategy == :hex and
                   (username == ^arg(:username) or
                      (not is_nil(^arg(:email)) and
                         string_downcase(email) == string_downcase(^arg(:email))))
               )
             )

      change set_attribute(:name, nil)
      change set_attribute(:email, nil)
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

    # The spend on resolution runs as whoever resolved the report, which for a
    # withdrawal is its reporter. The signal is what admits them, so they
    # never read these rows on a surface.
    policy action(:for_report) do
      authorize_if signal_in(Signals, :report_resolved)
    end

    policy action(:claim_for_identity) do
      authorize_if signal_in(Varsel.Accounts.Signals, :identity_linked)
    end

    policy action([:read, :for_identity, :link_user, :spend]) do
      authorize_if signal_in(Signals, :report_resolved)
      authorize_if signal_in(Varsel.Accounts.Signals, :identity_linked)
      authorize_if actor_attribute_equals(:system, :identity_claim)
      authorize_if actor_attribute_equals(:role, :poc)
    end

    # Only hex.pm says when it erased someone it named.
    policy action(:erase_hex_person) do
      access_type :strict
      authorize_if actor_attribute_equals(:system, :hexpm_intake)
    end
  end

  # The triage page shows participants on the report topic's subscription.
  pub_sub do
    module VarselWeb.Endpoint
    prefix "vulnerability_report"

    publish :erase_hex_person, ["all"]
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

  signals_in do
    from Signals do
      on :report_resolved, :spend, read_action: :for_report, args: [:report_id]
    end

    from Varsel.Accounts.Signals do
      on :identity_linked, :claim_for_identity
    end
  end

  identities do
    identity :unique_report_handle, [:report_id, :role, :strategy, :username]
  end
end
