# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Proposal do
  @moduledoc """
  A field-level change request against a case — the collaboration primitive
  for refining case data.

  A proposal addresses one thing: set a single field (on the case or on a
  child row), insert a child row, or delete one. The polymorphic target
  mechanism is documented on `Varsel.Cases.Proposal.Target`; the proposed
  value travels in a `%{"value" => ...}` envelope so "set to null" and
  "no value" stay distinguishable.

  Accepting a proposal applies it to the target inside one transaction, with
  the accepting user as actor (the paper trail on the target attributes the
  write to the approver; proposer provenance stays here). Competing open
  proposals for the same target/field are superseded automatically. Declining
  records a resolution note; authors can withdraw their own proposals.
  Counter-proposals link back via `parent_proposal_id`.

  Proposals can be *created* in every case state except `:closed`; they can
  only be *resolved* while the case content is editable (`:draft`/`:review`).
  """

  use Ash.Resource,
    otp_app: :varsel,
    domain: Varsel.Cases,
    authorizers: [Ash.Policy.Authorizer],
    data_layer: AshPostgres.DataLayer,
    extensions: [AshStateMachine, AshPaperTrail.Resource, AshGraphql.Resource],
    notifiers: [Ash.Notifier.PubSub]

  alias Varsel.Accounts.User
  alias Varsel.Cases.Proposal.Changes.ApplyToTarget
  alias Varsel.Cases.Proposal.Changes.EnsureOpen
  alias Varsel.Cases.Proposal.Changes.SupersedeCompeting
  alias Varsel.Cases.Proposal.Operation
  alias Varsel.Cases.Proposal.State
  alias Varsel.Cases.Proposal.Target
  alias Varsel.Cases.Proposal.Validations.CaseState
  alias Varsel.Cases.Proposal.Validations.ValidTarget

  graphql do
    type :case_proposal
  end

  postgres do
    table "case_proposals"
    repo Varsel.Repo

    references do
      reference :case, on_delete: :delete
      reference :parent_proposal, on_delete: :nilify
    end

    custom_indexes do
      index [:case_id, :state]
      index [:target, :target_id, :field_name], where: "state = 'open'"
    end
  end

  state_machine do
    initial_states [:open]
    default_initial_state :open

    transitions do
      transition :accept, from: :open, to: :accepted
      transition :decline, from: :open, to: :declined
      transition :supersede, from: :open, to: :superseded
      transition :withdraw, from: :open, to: :withdrawn
    end
  end

  paper_trail do
    change_tracking_mode :changes_only
    reference_source? false
    attributes_as_attributes [:state]
    ignore_attributes [:inserted_at, :updated_at]
    only_when_changed? true
    store_action_name? true
    belongs_to_actor :user, User, domain: Varsel.Accounts
  end

  actions do
    read :read do
      description "Reads proposals."
      primary? true
      # Keyset pagination keeps the action streamable, which the bulk
      # :supersede update relies on.
      pagination keyset?: true, required?: false
    end

    read :list_for_case do
      description "All proposals of a case, newest first."
      argument :case_id, :uuid, allow_nil?: false
      filter expr(case_id == ^arg(:case_id))
      prepare build(sort: [inserted_at: :desc])
    end

    read :list_open_for_case do
      description "Open (unresolved) proposals of a case."
      argument :case_id, :uuid, allow_nil?: false
      filter expr(case_id == ^arg(:case_id) and state == :open)
      prepare build(sort: [inserted_at: :asc])
    end

    create :propose do
      description """
      Creates a change request against a case. Exactly one of:
      set one field (operation :set, field_name + proposed_value), add a child
      row (:insert, proposed_value is the row payload; target_id references
      the parent affected_package for package_channel/version_event targets),
      or remove a child row (:delete, target_id references the row).
      The proposed value travels in a {"value": ...} envelope.

      An affected_package :insert payload may instead name a well-known
      product preset: {"preset": "otp" | "elixir" | "gleam",
      "applications": [...], "introduced_commit": sha,
      "fixed_commits": [sha, ...], "program_files": [{"path":
      "lib/ssh/src/ssh_sftpd.erl", "modules": ["ssh_sftpd"], "routines":
      ["ssh_sftpd:handle_op/4"]}, ...]}. Paths are repository-root-relative;
      each rendered entry scopes files/modules/routines to its channel's
      subpath (prefilled per application by the presets). Accepting the
      proposal creates the package with vendor/product/repo/CPE prefilled
      plus one pkg:otp/<application> channel per affected application
      (otp/elixir; gleam takes no applications and gets its sid + OCI
      channels) and one version boundary fact per commit. When vulnerable code moved between OTP applications
      over time, additionally propose channel-scoped explicit version events
      bounding the former application's channel.
      """

      accept [
        :case_id,
        :target,
        :target_id,
        :operation,
        :field_name,
        :proposed_value,
        :reasoning,
        :parent_proposal_id
      ]

      change relate_actor(:author)

      validate {CaseState,
                states: [:draft, :review, :approved, :publishing, :published],
                message: "proposals cannot be created on a closed case"}

      # The validation needs target/operation present (the MCP permission
      # check probes the action with empty input).
      validate ValidTarget, only_when_valid?: true
    end

    update :accept do
      description """
      Accepts a proposal: applies the change to its target (as the accepting
      user) and supersedes competing open proposals, all in one transaction.
      """

      primary? true

      accept [:resolution_note]
      require_atomic? false

      change get_and_lock_for_update()
      change EnsureOpen
      change transition_state(:accepted)
      change relate_actor(:resolved_by)
      change set_attribute(:resolved_at, &DateTime.utc_now/0)

      validate {CaseState,
                states: [:draft, :review],
                message:
                  "proposals can only be accepted while the case is editable (currently %{state}); reopen the case first"}

      change ApplyToTarget
      change SupersedeCompeting
    end

    update :decline do
      description "Declines a proposal with an optional resolution note."
      accept [:resolution_note]
      require_atomic? false

      change get_and_lock_for_update()
      change EnsureOpen
      change transition_state(:declined)
      change relate_actor(:resolved_by)
      change set_attribute(:resolved_at, &DateTime.utc_now/0)
    end

    update :withdraw do
      description "The author retracts their own open proposal."
      accept []
      require_atomic? false

      change get_and_lock_for_update()
      change EnsureOpen
      change transition_state(:withdrawn)
      change set_attribute(:resolved_at, &DateTime.utc_now/0)
    end

    update :supersede do
      description "Internal: marks a proposal obsolete (accepted competitor, deleted target row, or closed case)."
      accept [:resolution_note]
      require_atomic? false

      change get_and_lock_for_update()
      change EnsureOpen
      change transition_state(:superseded)
      change set_attribute(:resolved_at, &DateTime.utc_now/0)
    end
  end

  policies do
    # POCs and assigned supporters see a case's proposals; authors always see
    # their own.
    policy action_type(:read) do
      authorize_if actor_attribute_equals(:role, :poc)
      authorize_if relates_to_actor_via([:case, :assignments, :user])
      authorize_if expr(author_id == ^actor(:id))
    end

    policy action([:propose, :accept, :decline]) do
      authorize_if actor_attribute_equals(:role, :poc)
      authorize_if relates_to_actor_via([:case, :assignments, :user])
    end

    policy action(:withdraw) do
      authorize_if actor_attribute_equals(:role, :poc)
      authorize_if expr(author_id == ^actor(:id))
    end

    # Internal only — invoked from sweep changes with authorize?: false.
    policy action(:supersede) do
      authorize_if actor_attribute_equals(:role, :poc)
    end
  end

  pub_sub do
    module VarselWeb.Endpoint
    prefix "case_proposal"

    publish_all :create, [[:case_id]]
    publish_all :update, [[:case_id]]
  end

  attributes do
    uuid_primary_key :id

    attribute :target, Target do
      description "Which kind of resource this proposal addresses."
      allow_nil? false
      public? true
    end

    attribute :target_id, :uuid do
      description """
      The addressed row (:set/:delete on a child), the parent affected_package
      (:insert of a package_channel/version_event), or nil (the case itself /
      an insert directly under the case). Deliberately no FK — polymorphic.
      """

      public? true
    end

    attribute :operation, Operation do
      allow_nil? false
      public? true
    end

    attribute :field_name, :string do
      description "The field a :set proposal changes."
      public? true
    end

    attribute :proposed_value, :map do
      description "Envelope {\"value\" => ...} carrying the proposed value or :insert row payload."
      public? true
    end

    attribute :reasoning, :string do
      description "Markdown justification for the proposed change."
      public? true
    end

    attribute :state, State do
      description "Lifecycle state of the proposal."
      allow_nil? false
      default :open
      public? true
    end

    attribute :resolution_note, :string do
      description "Why the proposal was accepted/declined/superseded."
      public? true
    end

    attribute :resolved_at, :utc_datetime_usec do
      public? true
    end

    attribute :applied_target_id, :uuid do
      description "For an accepted :insert — the id of the row it created."
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

    belongs_to :author, User do
      description "Who made the proposal. Set from the actor."
      allow_nil? false
      public? true
    end

    belongs_to :resolved_by, User do
      description "Who accepted or declined the proposal."
      allow_nil? true
      public? true
    end

    belongs_to :parent_proposal, __MODULE__ do
      description "The proposal this one counters."
      allow_nil? true
      public? true
      attribute_writable? true
    end

    has_many :counter_proposals, __MODULE__ do
      public? true
      destination_attribute :parent_proposal_id
    end

    has_many :comments, Varsel.Cases.Comment do
      public? true
      destination_attribute :proposal_id
    end
  end
end
