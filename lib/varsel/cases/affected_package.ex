# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.AffectedPackage do
  @moduledoc """
  One *logical product* affected by the case's vulnerability (e.g. "Erlang/OTP"
  or "ash_authentication_phoenix").

  A logical product is published as one or more `affected[]` entries — one per
  distribution channel (`Varsel.Cases.PackageChannel`): a Hex package gets a
  registry entry plus a GitHub entry, OTP gets a `pkg:otp/<app>` entry plus the
  `erlang/otp` GitHub entry, and so on. The vulnerability boundary *facts*
  (introduced/fixed commits or explicit version boundaries) live on
  `Varsel.Cases.VersionEvent` rows and are expanded to version ranges at render
  time by `Varsel.Cases.Derivation`.

  `derivation_cache` holds the most recent derivation result purely for fast
  previews and diffing; publishing always recomputes it.
  """

  use Ash.Resource,
    otp_app: :varsel,
    domain: Varsel.Cases,
    authorizers: [Ash.Policy.Authorizer],
    data_layer: AshPostgres.DataLayer,
    extensions: [AshPaperTrail.Resource, AshGraphql.Resource]

  alias Varsel.Cases.AffectedPackage.DefaultStatus
  alias Varsel.Cases.Changes.ApplyProposedField
  alias Varsel.Cases.Changes.SupersedeOrphanedProposals
  alias Varsel.Cases.Checks.ActorAssignedToCase
  alias Varsel.Cases.Proposable
  alias Varsel.Cases.Validations.CaseEditable

  graphql do
    type :case_affected_package
  end

  postgres do
    table "case_affected_packages"
    repo Varsel.Repo

    references do
      reference :case, on_delete: :delete
    end
  end

  paper_trail do
    change_tracking_mode :changes_only
    reference_source? false
    ignore_attributes [:derivation_cache, :derivation_cached_at, :inserted_at, :updated_at]
    only_when_changed? true
    store_action_name? true
    belongs_to_actor :user, Varsel.Accounts.User, domain: Varsel.Accounts
  end

  actions do
    defaults [:read]

    create :add do
      description "Adds a logical product to a case."
      accept [:case_id | Proposable.fields(__MODULE__)]
      validate CaseEditable
    end

    update :edit do
      description "Edits a logical product. Only allowed while the case is editable."
      accept Proposable.fields(__MODULE__)
      require_atomic? false
      validate CaseEditable
    end

    destroy :remove do
      description "Removes a logical product (with all its channels and version events) from a case."
      require_atomic? false
      validate CaseEditable
      change SupersedeOrphanedProposals
    end

    update :apply_proposal do
      description "Internal: applies one accepted proposal value to a single field."
      accept []
      require_atomic? false

      argument :field, :string, allow_nil?: false
      argument :value, :term
      argument :proposal_id, :uuid, allow_nil?: false

      validate CaseEditable
      change ApplyProposedField
    end

    create :apply_proposal_insert do
      description "Internal: creates the row proposed by an accepted :insert proposal."
      accept [:case_id | Proposable.fields(__MODULE__)]

      argument :proposal_id, :uuid, allow_nil?: false

      validate CaseEditable
    end

    destroy :apply_proposal_delete do
      description "Internal: removes the row targeted by an accepted :delete proposal."
      require_atomic? false

      argument :proposal_id, :uuid, allow_nil?: false

      validate CaseEditable
      change SupersedeOrphanedProposals
    end

    update :store_derivation do
      description "Internal: caches the latest derivation result for previews."
      accept [:derivation_cache]
      require_atomic? false
      change set_attribute(:derivation_cached_at, &DateTime.utc_now/0)
    end
  end

  policies do
    bypass AshOban.Checks.AshObanInteraction do
      authorize_if always()
    end

    policy action_type(:read) do
      authorize_if actor_attribute_equals(:role, :poc)
      authorize_if expr(exists(case.assignments, user_id == ^actor(:id)))
    end

    policy action_type([:create, :update, :destroy]) do
      authorize_if actor_attribute_equals(:role, :poc)
      authorize_if ActorAssignedToCase
    end
  end

  attributes do
    uuid_primary_key :id

    attribute :vendor, :string do
      description ~s{Rendered as affected[].vendor (e.g. "Erlang", "ash-project").}
      allow_nil? false
      public? true
    end

    attribute :product, :string do
      description ~s{Rendered as affected[].product (e.g. "OTP", "ash_authentication_phoenix").}
      allow_nil? false
      public? true
    end

    attribute :repo_url, :string do
      description "Source repository URL (affected[].repo). Nil for hosted services."
      public? true
    end

    attribute :cpe, :string do
      description """
      CPE 2.3 base string (affected[].cpes). Defaults to
      cpe:2.3:a:<vendor>:<product>:*:*:*:*:*:*:*:* at render time when nil.
      """

      public? true
    end

    attribute :default_status, DefaultStatus do
      description "affected[].defaultStatus for every rendered channel entry."
      allow_nil? false
      default :unaffected
      public? true
    end

    attribute :modules, {:array, :string} do
      description "Affected modules (affected[].modules), e.g. [\"ssh\"]."
      allow_nil? false
      default []
      public? true
    end

    attribute :program_files, {:array, :string} do
      description "Affected source files (affected[].programFiles)."
      allow_nil? false
      default []
      public? true
    end

    attribute :program_routines, {:array, :string} do
      description """
      Affected functions in Erlang notation (affected[].programRoutines[].name),
      e.g. [\"zip:unzip/1\", \"'Elixir.Plug.Conn':send_resp/3\"].
      """

      allow_nil? false
      default []
      public? true
    end

    attribute :platforms, {:array, :string} do
      description "Affected platforms (affected[].platforms). Rarely used."
      allow_nil? false
      default []
      public? true
    end

    attribute :allow_unreleased_fix, :boolean do
      description """
      Escape hatch: allow publishing while a fixed commit has no containing
      release yet (the fix boundary renders as open-ended).
      """

      allow_nil? false
      default false
      public? true
    end

    attribute :position, :integer do
      description "Order of this product's entries within affected[]."
      allow_nil? false
      default 0
      public? true
    end

    attribute :derivation_cache, :map do
      description "Latest derivation result (per-channel version ranges). Never authoritative."
    end

    attribute :derivation_cached_at, :utc_datetime

    timestamps()
  end

  relationships do
    belongs_to :case, Varsel.Cases.Case do
      allow_nil? false
      public? true
      attribute_writable? true
    end

    has_many :channels, Varsel.Cases.PackageChannel do
      public? true
      sort position: :asc
    end

    has_many :version_events, Varsel.Cases.VersionEvent do
      public? true
    end
  end
end
