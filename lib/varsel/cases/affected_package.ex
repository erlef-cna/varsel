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

  Well-known products are added through the specialized `add_otp` /
  `add_elixir` / `add_gleam` actions, which prefill the package constants and
  expand applications/commits into channels and version events from
  `Varsel.Cases.AffectedPackage.Preset`.

  `derivation_cache` holds the most recent derivation result purely for fast
  previews and diffing; publishing always recomputes it.
  """

  use Ash.Resource,
    otp_app: :varsel,
    domain: Varsel.Cases,
    authorizers: [Ash.Policy.Authorizer],
    data_layer: AshPostgres.DataLayer,
    extensions: [AshPaperTrail.Resource, AshGraphql.Resource],
    notifiers: [Ash.Notifier.PubSub]

  alias Varsel.Cases.AffectedPackage.Changes.FromPreset
  alias Varsel.Cases.AffectedPackage.DefaultStatus
  alias Varsel.Cases.AffectedPackage.Preset
  alias Varsel.Cases.AffectedPackage.ProgramFile
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

    create :add_otp do
      description """
      Adds Erlang/OTP as an affected product: prefills vendor/product/repo/CPE
      as the published records spell them, creates one pkg:otp/<application>
      channel per affected OTP application and version boundary facts from the
      given commits. When vulnerable code moved between applications over time,
      bound the former application's channel with channel-scoped explicit
      version events afterwards.
      """

      accept [:case_id, :program_files]

      argument :applications, {:array, :string} do
        description ~s{Affected OTP applications (e.g. ["ssh"]); one pkg:otp channel each.}
        allow_nil? false
        constraints min_length: 1, items: [allow_empty?: false]
      end

      argument :introduced_commit, :string do
        description "Full SHA of the commit introducing the vulnerability."
        constraints match: Preset.commit_sha_regex()
      end

      argument :fixed_commits, {:array, :string} do
        description "Full SHAs of the fix commits, one per patched release branch."
        default []
        constraints items: [match: Preset.commit_sha_regex()]
      end

      validate CaseEditable
      change {FromPreset, preset: :otp}
    end

    create :add_elixir do
      description """
      Adds Elixir as an affected product: prefills vendor/product/repo as the
      published records spell them, creates one pkg:otp/<application> channel
      per affected Elixir application (elixir, eex, ex_unit, iex, logger, mix)
      and version boundary facts from the given commits.
      """

      accept [:case_id, :program_files]

      argument :applications, {:array, :string} do
        description ~s{Affected Elixir applications (e.g. ["elixir"] or ["mix"]).}
        allow_nil? false
        constraints min_length: 1, items: [allow_empty?: false]
      end

      argument :introduced_commit, :string do
        description "Full SHA of the commit introducing the vulnerability."
        constraints match: Preset.commit_sha_regex()
      end

      argument :fixed_commits, {:array, :string} do
        description "Full SHAs of the fix commits, one per patched release branch."
        default []
        constraints items: [match: Preset.commit_sha_regex()]
      end

      validate CaseEditable
      change {FromPreset, preset: :elixir}
    end

    create :add_gleam do
      description """
      Adds Gleam as an affected product: prefills vendor/product/repo/CPE as
      the published records spell them, creates the pkg:sid/gleam.run/gleam
      channel plus the ghcr.io OCI image channel (with its tag flavors) and
      version boundary facts from the given commits.
      """

      accept [:case_id, :program_files]

      argument :introduced_commit, :string do
        description "Full SHA of the commit introducing the vulnerability."
        constraints match: Preset.commit_sha_regex()
      end

      argument :fixed_commits, {:array, :string} do
        description "Full SHAs of the fix commits, one per patched release branch."
        default []
        constraints items: [match: Preset.commit_sha_regex()]
      end

      validate CaseEditable
      change {FromPreset, preset: :gleam}
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

    create :apply_proposal_insert_otp do
      description "Internal: creates the Erlang/OTP package proposed by an accepted preset :insert proposal."
      accept [:case_id, :program_files]

      argument :applications, {:array, :string} do
        allow_nil? false
        constraints min_length: 1, items: [allow_empty?: false]
      end

      argument :introduced_commit, :string do
        constraints match: Preset.commit_sha_regex()
      end

      argument :fixed_commits, {:array, :string} do
        default []
        constraints items: [match: Preset.commit_sha_regex()]
      end

      argument :proposal_id, :uuid, allow_nil?: false

      validate CaseEditable
      change {FromPreset, preset: :otp}
    end

    create :apply_proposal_insert_elixir do
      description "Internal: creates the Elixir package proposed by an accepted preset :insert proposal."
      accept [:case_id, :program_files]

      argument :applications, {:array, :string} do
        allow_nil? false
        constraints min_length: 1, items: [allow_empty?: false]
      end

      argument :introduced_commit, :string do
        constraints match: Preset.commit_sha_regex()
      end

      argument :fixed_commits, {:array, :string} do
        default []
        constraints items: [match: Preset.commit_sha_regex()]
      end

      argument :proposal_id, :uuid, allow_nil?: false

      validate CaseEditable
      change {FromPreset, preset: :elixir}
    end

    create :apply_proposal_insert_gleam do
      description "Internal: creates the Gleam package proposed by an accepted preset :insert proposal."
      accept [:case_id, :program_files]

      argument :introduced_commit, :string do
        constraints match: Preset.commit_sha_regex()
      end

      argument :fixed_commits, {:array, :string} do
        default []
        constraints items: [match: Preset.commit_sha_regex()]
      end

      argument :proposal_id, :uuid, allow_nil?: false

      validate CaseEditable
      change {FromPreset, preset: :gleam}
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

  pub_sub do
    module VarselWeb.Endpoint
    prefix "case"

    publish_all :create, [[:case_id]]
    publish_all :update, [[:case_id]]
    publish_all :destroy, [[:case_id]]
  end

  validations do
    validate Varsel.Cases.Validations.RepoUrlHttps
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
      description "Source repository URL (affected[].repo), https:// only. Nil for hosted services."
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

    attribute :program_files, {:array, ProgramFile} do
      description """
      Affected source files with the modules/routines each contributes
      (affected[].programFiles/modules/programRoutines). Paths are
      repository-root-relative; channels with a subpath render only the files
      under it (paths relative to it), the git entry renders all of them
      under their full paths.
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
