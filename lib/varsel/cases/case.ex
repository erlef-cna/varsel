# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Case do
  @moduledoc """
  The structured, editorial representation of one vulnerability from intake to
  publication — everything needed to render a full CVE JSON 5.2 CNA container.

  A case stores *facts* (markdown prose, a CVSS vector, affected packages with
  their distribution channels and version boundary events, references, credits,
  CWE/CAPEC classifications). Derived data — version ranges deduced from commit
  SHAs, enumerated versions, `cpeApplicability` — is computed at render time by
  `Varsel.Cases.Derivation` / `Varsel.Cases.Render`, never stored.

  `Varsel.CVE.CveRecord` stays the MITRE-facing shell: a case renders to a CNA
  container and hands it to the existing publish machinery.

  ## State machine

  ```mermaid
  stateDiagram-v2
    [*] --> draft : open
    draft --> review : request_review
    review --> draft : request_changes
    review --> approved : approve (POC)
    approved --> publishing : publish (POC)
    publishing --> published : mark_published (system)
    review --> draft : reopen
    approved --> draft : reopen
    published --> draft : reopen (amendment)
    draft --> closed : close
    review --> closed : close
  ```

  Content (case fields and all child rows) is editable only in `:draft` and
  `:review` — the `Varsel.Cases.Validations.CaseEditable` freeze. Amending a
  published case means reopening it; the next publish pushes a MITRE update.

  ## Escape hatch

  `cna_override` is an RFC 7396 JSON Merge Patch applied to the fully rendered
  CNA container as the last render step, for truly non-standard records.
  Narrower overrides live on `Varsel.Cases.PackageChannel`.
  """

  use Ash.Resource,
    otp_app: :varsel,
    domain: Varsel.Cases,
    authorizers: [Ash.Policy.Authorizer],
    data_layer: AshPostgres.DataLayer,
    extensions: [AshStateMachine, AshOban, AshPaperTrail.Resource, AshGraphql.Resource],
    notifiers: [Ash.Notifier.PubSub]

  alias Varsel.Cases.Case.Discovery
  alias Varsel.Cases.Case.State
  alias Varsel.Cases.Case.TimelineEntry
  alias Varsel.Cases.Checks.ActorAssignedToCase
  alias Varsel.Cases.Publication
  alias Varsel.Cases.Validations.CaseEditable

  @content_fields [
    :title,
    :description_md,
    :workarounds_md,
    :configurations_md,
    :solutions_md,
    :discovery,
    :cvss_v4,
    :date_public,
    :timeline,
    :internal_notes,
    :cna_override
  ]

  graphql do
    type :case
  end

  postgres do
    table "cases"
    repo Varsel.Repo

    references do
      reference :cve_record, on_delete: :nilify
    end
  end

  state_machine do
    initial_states [:draft]
    default_initial_state :draft

    transitions do
      transition :request_review, from: :draft, to: :review
      transition :request_changes, from: :review, to: :draft
      transition :approve, from: :review, to: :approved
      transition :publish, from: :approved, to: :publishing
      transition :mark_published, from: :publishing, to: :published
      transition :reopen, from: [:review, :approved, :published], to: :draft
      transition :close, from: [:draft, :review], to: :closed
    end
  end

  oban do
    triggers do
      # Safety net for the publish handoff: Varsel.Cases.Case.Notifier runs
      # this trigger the moment the backing CveRecord changes; the scheduler
      # catches anything the notifier missed (e.g. a node restart).
      trigger :mark_published do
        action :mark_published
        where expr(state == :publishing and cve_record.state == :published)
        worker_module_name Varsel.Cases.Case.MarkPublishedWorker
        scheduler_module_name Varsel.Cases.Case.MarkPublishedScheduler
        queue :cve_publishing
        max_attempts 3
        scheduler_cron "*/15 * * * *"
        worker_opts unique: [period: :infinity, states: :incomplete, keys: [:primary_key]]
      end
    end
  end

  paper_trail do
    change_tracking_mode :changes_only
    reference_source? false
    # `state` is a custom Ash.Type.Enum; store it as its own version column
    # rather than serializing it into the `changes` map (which AshPaperTrail
    # cannot do for enum types).
    attributes_as_attributes [:state]
    ignore_attributes [:inserted_at, :updated_at]
    only_when_changed? true
    store_action_name? true
    belongs_to_actor :user, Varsel.Accounts.User, domain: Varsel.Accounts
  end

  actions do
    defaults [:read]

    read :list_cases do
      description "Lists cases in every state, most recently updated first."
      prepare build(sort: [updated_at: :desc])

      pagination offset?: true,
                 keyset?: true,
                 countable: :by_default,
                 default_limit: 25,
                 required?: false
    end

    create :open do
      description "Opens a new case in the :draft state."
      accept @content_fields
    end

    update :edit do
      description "Edits case content. Only allowed while the case is in :draft or :review."
      accept @content_fields
      require_atomic? false
      validate CaseEditable
    end

    update :apply_proposal do
      description """
      Internal: applies one accepted proposal value to a single case field.
      Invoked from Varsel.Cases.Proposal's accept action with the accepting
      user as actor, so the paper trail attributes the write to the approver.
      """

      accept []
      require_atomic? false

      argument :field, :string, allow_nil?: false
      argument :value, :term
      argument :proposal_id, :uuid, allow_nil?: false

      validate CaseEditable
      change Varsel.Cases.Changes.ApplyProposedField
    end

    action :render_preview, :map do
      description """
      Renders the case to its CNA container without publishing: returns the
      container, the validation result, which override escape hatches fired,
      and any conditions that would block publishing. Uses cached derivations
      (refresh_derivation recomputes them).
      """

      argument :id, :uuid, allow_nil?: false

      run fn input, context ->
        with {:ok, case_record} <-
               Ash.get(__MODULE__, input.arguments.id, actor: context.actor, authorize?: true),
             {:ok, %{result: result, cve_json: cve_json}} <-
               Publication.render(case_record) do
          validation = cve_json && Publication.validate(cve_json)

          {:ok,
           %{
             "cna" => result.cna,
             "cve_json" => cve_json,
             "blockers" => result.blockers,
             "overrides_applied" => result.overrides_applied,
             "validation" => validation && Map.take(validation, [:valid, :errors])
           }}
        end
      end
    end

    update :refresh_derivation do
      description "Recomputes the derived version data (SHA → version ranges) of every affected package."
      accept []
      require_atomic? false

      change Varsel.Cases.Case.Changes.RefreshDerivation
    end

    update :request_review do
      description "Marks a drafted case ready for POC review."
      accept []
      change transition_state(:review)
    end

    update :request_changes do
      description "POC sends a case in review back to drafting."
      accept []
      change transition_state(:draft)
    end

    update :approve do
      description "POC signs off on the case content; the case is frozen until published or reopened."
      accept []
      change transition_state(:approved)
    end

    update :assign_cve_id do
      description """
      Assigns a CVE ID to the case, taking a reserved record out of the open
      pool (or linking the given one). No state transition; allowed any time
      before the case is published.
      """

      accept []
      require_atomic? false

      argument :cve_record_id, :uuid do
        description "A specific reserved CVE record to assign. Defaults to the lowest free ID of the current year."
      end

      change Varsel.Cases.Case.Changes.AssignCveRecord
    end

    update :publish do
      description """
      Renders the case to a CNA container, validates it, and hands it to the
      CVE record publish machinery (request_publish for a first publish,
      update for an amendment). The case tracks the handoff as :publishing
      until the record reaches MITRE.
      """

      accept []
      require_atomic? false

      change transition_state(:publishing)
      change Varsel.Cases.Case.Changes.PublishToCveRecord
    end

    update :mark_published do
      description "System action: marks the case published once its CVE record reached MITRE."
      accept []
      require_atomic? false

      change transition_state(:published)
      change Varsel.Cases.Case.Changes.StampPublishedAt
    end

    update :reopen do
      description """
      Reopens a case for editing. Reopening a published case starts an
      amendment: the next publish pushes an update to MITRE.
      """

      accept []
      change transition_state(:draft)
    end

    update :close do
      description """
      Terminally closes a case that will not (or no longer) result in a
      published CVE. If a CVE ID is already assigned, the caller must either
      reject the ID at MITRE (reject_cve_id: true) or explicitly acknowledge
      parking it (acknowledge_parked_cve_id: true) — an assigned ID cannot
      silently return to the pool.
      """

      accept [:closed_reason]
      require_atomic? false

      argument :reject_cve_id, :boolean, default: false
      argument :acknowledge_parked_cve_id, :boolean, default: false

      change transition_state(:closed)
      change Varsel.Cases.Case.Changes.HandleCveRecordOnClose
      change Varsel.Cases.Case.Changes.SweepOpenProposals
    end
  end

  policies do
    bypass AshOban.Checks.AshObanInteraction do
      authorize_if always()
    end

    # POCs see every case; supporters only cases they are assigned to.
    policy action_type(:read) do
      authorize_if actor_attribute_equals(:role, :poc)
      authorize_if expr(exists(assignments, user_id == ^actor(:id)))
    end

    # Content edits and review handoff: POC or assigned supporter.
    policy action([:edit, :apply_proposal, :request_review, :refresh_derivation]) do
      authorize_if actor_attribute_equals(:role, :poc)
      authorize_if ActorAssignedToCase
    end

    # The preview loads the case with authorization — the read policy above
    # scopes what any actor can render.
    policy action(:render_preview) do
      authorize_if actor_present()
    end

    # Case lifecycle decisions are POC-only.
    policy action([:open, :request_changes, :approve, :assign_cve_id, :publish, :reopen, :close]) do
      authorize_if actor_attribute_equals(:role, :poc)
    end

    # :mark_published runs only through the AshOban bypass above.
    policy action(:mark_published) do
      forbid_if always()
    end
  end

  pub_sub do
    module VarselWeb.Endpoint
    prefix "case"

    # A single stable topic for list views plus a per-case topic for detail views.
    publish_all :create, ["all"]
    publish_all :update, ["all"]
    publish_all :update, [[:id]]
    publish_all :destroy, ["all"]
  end

  attributes do
    uuid_primary_key :id

    attribute :state, State do
      description "Lifecycle state of the case."
      allow_nil? false
      default :draft
      public? true
    end

    attribute :title, :string do
      description "The CVE title (containers.cna.title). Required to publish."
      public? true
    end

    attribute :description_md, :string do
      description "Markdown source of the CVE description. Required to publish."
      public? true
    end

    attribute :workarounds_md, :string do
      description "Markdown workarounds; omitted from the record when nil."
      public? true
    end

    attribute :configurations_md, :string do
      description "Markdown configuration preconditions; omitted when nil."
      public? true
    end

    attribute :solutions_md, :string do
      description "Markdown solution description; omitted when nil."
      public? true
    end

    attribute :discovery, Discovery do
      description "How the vulnerability was discovered (source.discovery)."
      allow_nil? false
      default :unknown
      public? true
    end

    attribute :cvss_v4, Varsel.Types.CVSS do
      description "CVSS v4.0 vector. Score/severity/full metric object are derived at render time. Required to publish."
      constraints version: [:v4]
      public? true
    end

    attribute :date_public, :utc_datetime do
      description "When the vulnerability was publicly disclosed (datePublic); omitted when nil."
      public? true
    end

    attribute :timeline, {:array, TimelineEntry} do
      description "Significant events, rendered as timeline[]. Rarely used."
      allow_nil? false
      default []
      public? true
    end

    attribute :cna_override, :map do
      description """
      Escape hatch: RFC 7396 JSON Merge Patch applied to the fully rendered
      CNA container as the final render step.
      """

      public? true
    end

    attribute :internal_notes, :string do
      description "Internal working notes. Never rendered into the record."
      public? true
    end

    attribute :closed_reason, :string do
      description "Why the case was closed."
      public? true
    end

    attribute :published_at, :utc_datetime do
      description "When the case was first successfully published to MITRE."
      public? true
    end

    timestamps()
  end

  relationships do
    belongs_to :cve_record, Varsel.CVE.CveRecord do
      description "The reserved/published MITRE CVE record backing this case."
      public? true
    end

    has_many :assignments, Varsel.Cases.CaseAssignment do
      public? true
    end

    has_many :affected_packages, Varsel.Cases.AffectedPackage do
      public? true
      sort position: :asc
    end

    has_many :references, Varsel.Cases.CaseReference do
      public? true
      sort position: :asc
    end

    has_many :credits, Varsel.Cases.CaseCredit do
      public? true
      sort position: :asc
    end

    has_many :weaknesses, Varsel.Cases.CaseWeakness do
      public? true
      sort position: :asc
    end

    has_many :impacts, Varsel.Cases.CaseImpact do
      public? true
      sort position: :asc
    end

    has_many :proposals, Varsel.Cases.Proposal do
      public? true
    end

    has_many :comments, Varsel.Cases.Comment do
      public? true
    end

    has_many :vulnerability_reports, Varsel.CVE.VulnerabilityReport do
      description "Inbound reports consolidated into this case."
      public? true
    end
  end

  calculations do
    calculate :cve_id, :string, expr(cve_record.cve_id) do
      description "The assigned CVE ID, if any."
      public? true
    end
  end

  identities do
    identity :unique_cve_record, [:cve_record_id]
  end
end
