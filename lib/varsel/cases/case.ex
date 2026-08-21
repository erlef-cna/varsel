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
  `:review` — enforced by the content-freeze policy on `:edit` /
  `:apply_proposal`, with the `:version` optimistic lock rejecting writes from
  stale snapshots. Amending a published case means reopening it; the next
  publish pushes a MITRE update.

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

  alias Varsel.Cases.AffectedPackage.DerivationState
  alias Varsel.Cases.Case.Discovery
  alias Varsel.Cases.Case.State
  alias Varsel.Cases.Case.TimelineEntry
  alias Varsel.Cases.Changes.AssignOpener
  alias Varsel.Cases.Validations.CveIdAssignable

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
    ignore_attributes [:inserted_at, :updated_at, :version]
    only_when_changed? true
    store_action_name? true
    belongs_to_actor :user, Varsel.Accounts.User, domain: Varsel.Accounts
    version_extensions extensions: [Varsel.Accounts.VersionActorReference]
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
      description "Opens a new case in the :draft state, assigned to whoever opened it."
      # Opening an empty case is how a case normally starts; :adopt_cve_record
      # is the narrower path for a record that already exists elsewhere.
      primary? true
      accept @content_fields

      argument :assignments, {:array, :map} do
        public? false
      end

      change AssignOpener
      change manage_relationship(:assignments, type: :create)
    end

    create :adopt_cve_record do
      description """
      Opens a draft case around an existing CVE record — one created by hand or
      in the legacy management system — filling it in from the record's
      published CNA container. See `Varsel.Cases.Case.Import` for what a
      container can and cannot be read back into.
      """

      accept []

      argument :cve_record_id, :uuid do
        allow_nil? false
        description "The existing CVE record to manage as a case. It must not already have one."
      end

      argument :assignments, {:array, :map} do
        public? false
      end

      validate Varsel.Cases.Validations.CveRecordAdoptable

      change AssignOpener
      change manage_relationship(:assignments, type: :create)
      change Varsel.Cases.Case.Changes.AdoptCveRecord
    end

    update :edit do
      description "Edits case content. Only allowed while the case is in :draft or :review."
      primary? true
      accept @content_fields
      require_atomic? false
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

      change Varsel.Cases.Changes.ApplyProposedField
    end

    update :refresh_derivation do
      description "Recomputes and caches the derived version data (SHA → version ranges) of every *accepted* affected package. Run this after accepting affected-package changes and before rendering the preview — the preview reads the cache and does not recompute it. A case with no accepted affected_package has nothing to derive."
      accept []
      require_atomic? false

      argument :refresh, :boolean do
        default false
        allow_nil? false

        description "Fetch the current state of each package repository before deriving, so tags pushed upstream since the last scan are seen. Set this when the repository may have changed: checking whether a pending fix has been released, or deriving right after a release."
      end

      change Varsel.Cases.Case.Changes.RefreshDerivation
    end

    update :grant_access do
      description """
      Puts someone on the case by their provider handle, whether or not they
      have an account here yet: an assignment when the handle is one we hold an
      identity for, an invite waiting for them when it is not. Which one the
      caller gets back is the only difference they see — they asked to give a
      person access, not to look up who exists.
      """

      accept []
      require_atomic? false

      argument :strategy, Varsel.Cases.CaseInvite.Strategy, allow_nil?: false
      argument :username, :string, allow_nil?: false

      change Varsel.Cases.Case.Changes.GrantAccess
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

      validate CveIdAssignable
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
    # Pre-flight visibility only (`Ash.can?`): at runtime this passes and the
    # `transition_state` validation stays the enforcement.
    policy action_type(:update) do
      authorize_if AshStateMachine.Checks.ValidNextState
    end

    bypass AshOban.Checks.AshObanInteraction do
      authorize_if always()
    end

    # Nothing about a case is public: a read needs someone to be asking, and
    # the read policy below then narrows to what that someone may see. Scoped
    # to reads so an action no policy names is forbidden by default rather than
    # granted to any signed-in user. Which cases they may see cannot be decided
    # here — `relates_to_actor_via` is a filter, and a strict policy has no row
    # to filter yet — so this gate only asks that someone is signed in.
    policy action_type(:read) do
      access_type :strict
      forbid_if actor_absent()
      authorize_if always()
    end

    # POCs see every case; everyone else only the cases they are assigned to,
    # which is the whole of an unroled collaborator's access.
    policy action_type(:read) do
      authorize_if actor_attribute_equals(:role, :poc)
      authorize_if relates_to_actor_via([:assignments, :user])
    end

    # Content edits and review handoff: POC or assigned supporter. An assigned
    # user with no role may propose and comment, but never write directly.
    policy action([:edit, :apply_proposal, :request_review, :refresh_derivation]) do
      authorize_if actor_attribute_equals(:role, :poc)

      authorize_if expr(
                     ^actor(:role) == :supporter and
                       exists(assignments, user_id == ^actor(:id))
                   )
    end

    # Content freeze: case content may only change in :draft or :review.
    policy action([:edit, :apply_proposal]) do
      authorize_if expr(state in [:draft, :review])
    end

    # Supporters open their own cases; POCs open any.
    policy action(:open) do
      authorize_if actor_attribute_equals(:role, :poc)
      authorize_if actor_attribute_equals(:role, :supporter)
    end

    # An assigned supporter takes the *next free* ID of the year; naming the
    # record — a withheld ID, or one out of sequence — stays a POC decision.
    # The forbid sits after the POC check, which short-circuits it, so it only
    # ever judges everyone else.
    policy action(:assign_cve_id) do
      authorize_if actor_attribute_equals(:role, :poc)
      forbid_if expr(not is_nil(^arg(:cve_record_id)))

      authorize_if expr(
                     ^actor(:role) == :supporter and
                       exists(assignments, user_id == ^actor(:id))
                   )
    end

    # Reopening puts a case back into drafting, which is work rather than a
    # CNA decision, so an assigned supporter may do it.
    policy action(:reopen) do
      authorize_if actor_attribute_equals(:role, :poc)

      authorize_if expr(
                     ^actor(:role) == :supporter and
                       exists(assignments, user_id == ^actor(:id))
                   )
    end

    # The rest of the lifecycle — approving and publishing above all — is the
    # CNA's own responsibility and stays with POCs.
    policy action([
             :adopt_cve_record,
             :request_changes,
             :approve,
             :publish,
             :close
           ]) do
      authorize_if actor_attribute_equals(:role, :poc)
    end

    policy action(:grant_access) do
      authorize_if actor_attribute_equals(:role, :poc)

      authorize_if expr(
                     ^actor(:role) == :supporter and
                       exists(assignments, user_id == ^actor(:id))
                   )
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

  changes do
    # Updates always run against server-loaded snapshots. Rejecting any write
    # whose row moved since that load (StaleRecord) is what entitles the
    # update policies to trust `changeset.data`. :refresh_derivation is exempt:
    # it only rewrites derived caches and runs nested inside :publish, where a
    # version bump would trip the outer changeset's own lock. :grant_access is
    # exempt for the same reason: it writes a child row and nothing on the case,
    # so locking it would make two people adding two different collaborators
    # collide.
    change optimistic_lock(:version),
      on: [:update],
      where: [negate(action_is([:refresh_derivation, :grant_access]))]
  end

  attributes do
    uuid_primary_key :id

    attribute :state, State do
      description "Lifecycle state of the case."
      allow_nil? false
      default :draft
      public? true
    end

    attribute :version, :integer do
      description "Optimistic lock counter; every update bumps it and rejects stale snapshots."
      allow_nil? false
      default 1
      public? false
    end

    attribute :title, :string do
      description "The CVE title (containers.cna.title). Required to publish."
      constraints max_length: 500
      public? true
    end

    attribute :description_md, :string do
      description """
      Markdown source of the CVE description — what the vulnerability IS. Required to publish.

      Do not list the affected versions here. The published record appends them
      itself ("This issue affects plug: from 0.1.0 before 1.16.6."), derived
      from the case's affected packages, so writing that sentence yourself would
      publish it twice.
      """

      constraints max_length: 50_000
      public? true
    end

    attribute :workarounds_md, :string do
      description "Markdown workarounds; omitted from the record when nil."
      constraints max_length: 50_000
      public? true
    end

    attribute :configurations_md, :string do
      description "Markdown configuration preconditions; omitted when nil."
      constraints max_length: 50_000
      public? true
    end

    attribute :solutions_md, :string do
      description "Markdown solution description; omitted when nil."
      constraints max_length: 50_000
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
      description "Markdown working notes for the case team. Never rendered into the record."
      constraints max_length: 50_000
      public? true
    end

    attribute :closed_reason, :string do
      description "Why the case was closed."
      constraints max_length: 2_000
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
      allow_nil? true
      public? true
    end

    has_many :assignments, Varsel.Cases.CaseAssignment do
      public? true
    end

    has_many :invites, Varsel.Cases.CaseInvite do
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

    calculate :affects_repo,
              :boolean,
              expr(fragment("regexp_replace(?, ?, '')", ^arg(:repo_url), "(\\.git)?/*$") in affected_repos) do
      description """
      Whether the case affects the given repository, comparing normalized URLs
      so `.git`, a trailing slash and casing do not matter.
      """

      public? true

      argument :repo_url, :ci_string do
        allow_nil? false
        constraints allow_empty?: false, trim?: true
      end
    end

    calculate :cvss_score, :float, Varsel.Cases.Case.Calculations.CvssScore do
      description "The CVSS v4.0 base score, or nil when the case has no CVSS vector yet."
      public? true
    end

    calculate :severity_bucket, :atom, Varsel.Cases.Case.Calculations.SeverityBucket do
      description """
      The severity rating (none/low/medium/high/critical) `:cvss` derived from
      the vector, or nil when the case has no CVSS vector yet.
      """

      public? true
      constraints one_of: [:none, :low, :medium, :high, :critical]
    end

    calculate :affected_summary,
              :string,
              Varsel.Cases.Case.Calculations.AffectedSummary do
      public? true
      filterable? false

      description """
      The "This issue affects …" sentence the published record appends to the
      description, derived from the case's affected packages. Read it to see
      what will ship; never write it into `description_md` yourself.
      """
    end

    calculate :derived_references,
              {:array, Varsel.Cases.Case.DerivedReference},
              Varsel.Cases.Case.Calculations.DerivedReferences do
      public? true
      filterable? false

      description """
      The references the published record adds on its own — the cna.erlef.org /
      osv.dev self-links and the fix-commit links — as rendered
      `{"url", "tags"}` maps. Read it to see what will ship; never store these
      as references yourself.
      """
    end

    calculate :preview,
              Varsel.Cases.Case.Calculations.Preview.Result,
              Varsel.Cases.Case.Calculations.Preview do
      public? true
      filterable? false

      description """
      The full CVE record, applied overrides and publish blockers — without
      publishing. Loadable only on a case the actor may read, so the case read
      policy is its authorization.
      """
    end

    calculate :validation,
              Varsel.CVE.CveValidation.Result,
              Varsel.Cases.Case.Calculations.Validation do
      public? true
      filterable? false

      description """
      The schema/cvelint/hex validation result (`valid` + `errors`) for the
      case's rendered record. Loadable only on a case the actor may read.
      """
    end

    calculate :published_cna, :map, Varsel.Cases.Case.Calculations.PublishedCna do
      filterable? false

      description """
      The CNA container currently published on the case's CVE record, or nil
      when the case was never published — for diffing against :preview.
      """
    end

    calculate :published_osv, :map, Varsel.Cases.Case.Calculations.PublishedOsv do
      filterable? false

      description """
      The OSV document currently published for the case's CVE record, or nil
      when there is none — for diffing against :preview.
      """
    end

    calculate :derivation_state, DerivationState, DerivationState.Worst do
      description """
      What this case's derived version data is worth as a whole: the state of
      whichever product most needs attention, since deriving runs case-wide and
      the record is only as trustworthy as its least-derived product. Nil for a
      case with no affected products.
      """

      public? true
    end
  end

  aggregates do
    list :affected_repos, :affected_packages, :normalized_repo_url do
      description "The normalized repository URLs of every package this case affects."
      sort []
    end

    list :package_derivation_states, :affected_packages, :derivation_state do
      description "Each affected product's derivation state, for the case-wide summary."
      sort []
    end

    max :derivation_cached_at, :affected_packages, :derivation_cached_at do
      description "When any of this case's products last derived."
    end
  end

  identities do
    identity :unique_cve_record, [:cve_record_id]
  end
end
