# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.PackageChannel do
  @moduledoc """
  One distribution channel of a `Varsel.Cases.AffectedPackage` — rendered as
  exactly one `affected[]` entry in the CNA container.

  The channel type fixes the entry's constants (collectionURL, purl scheme,
  versionType); `package_name` names the package within the channel. Version
  boundaries come from the package's `Varsel.Cases.VersionEvent` facts,
  resolved per channel by `Varsel.Cases.Derivation`.

  ## Escape hatches

  * `versions_override` — replaces the *derived* `versions[]` array wholesale
    with raw CVE-schema version objects, when derivation cannot express the
    real range structure.
  * `entry_override` — RFC 7396 JSON Merge Patch applied to this channel's
    fully rendered `affected[]` entry (add/replace/remove any key).
  """

  use Ash.Resource,
    otp_app: :varsel,
    domain: Varsel.Cases,
    authorizers: [Ash.Policy.Authorizer],
    data_layer: AshPostgres.DataLayer,
    extensions: [AshPaperTrail.Resource, AshGraphql.Resource]

  alias Varsel.Cases.Changes.ApplyProposedField
  alias Varsel.Cases.Changes.SupersedeOrphanedProposals
  alias Varsel.Cases.Checks.ActorAssignedToCase
  alias Varsel.Cases.PackageChannel.Changes.NormalizePackageName
  alias Varsel.Cases.PackageChannel.ChannelType
  alias Varsel.Cases.PackageChannel.Validations.ConsistentWithPackage
  alias Varsel.Cases.Proposable
  alias Varsel.Cases.Validations.CaseEditable

  graphql do
    type :case_package_channel
  end

  postgres do
    table "case_package_channels"
    repo Varsel.Repo

    references do
      reference :case, on_delete: :delete
      reference :affected_package, on_delete: :delete
    end
  end

  paper_trail do
    change_tracking_mode :changes_only
    reference_source? false
    ignore_attributes [:inserted_at, :updated_at]
    only_when_changed? true
    store_action_name? true
    belongs_to_actor :user, Varsel.Accounts.User, domain: Varsel.Accounts
  end

  actions do
    defaults [:read]

    create :add do
      description "Adds a distribution channel to a logical product."
      accept [:case_id, :affected_package_id | Proposable.fields(__MODULE__)]
      change NormalizePackageName
      validate CaseEditable
      validate ConsistentWithPackage
    end

    update :edit do
      description "Edits a channel. Only allowed while the case is editable."
      accept Proposable.fields(__MODULE__)
      require_atomic? false
      change NormalizePackageName
      validate CaseEditable
      validate ConsistentWithPackage
    end

    destroy :remove do
      description "Removes a channel from a logical product."
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
      validate ConsistentWithPackage
      change ApplyProposedField
      change NormalizePackageName
    end

    create :apply_proposal_insert do
      description "Internal: creates the row proposed by an accepted :insert proposal."
      accept [:case_id, :affected_package_id | Proposable.fields(__MODULE__)]

      argument :proposal_id, :uuid, allow_nil?: false

      change NormalizePackageName
      validate CaseEditable
      validate ConsistentWithPackage
    end

    destroy :apply_proposal_delete do
      description "Internal: removes the row targeted by an accepted :delete proposal."
      require_atomic? false

      argument :proposal_id, :uuid, allow_nil?: false

      validate CaseEditable
      change SupersedeOrphanedProposals
    end
  end

  policies do
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

    attribute :channel_type, ChannelType do
      allow_nil? false
      public? true
    end

    attribute :package_name, :string do
      description """
      Package name within the channel, e.g. "ash_authentication_phoenix" (hex),
      "team-alembic/ash_authentication_phoenix" (git), "stdlib" (otp),
      "gleam" (oci). Nil only for :hosted channels.
      """

      public? true
    end

    attribute :registry_url, :string do
      description "Registry namespace for :oci channels (e.g. \"ghcr.io/gleam-lang\") or an npm registry override."
      public? true
    end

    attribute :tag_suffixes, {:array, :string} do
      description """
      OCI image-tag flavor suffixes (e.g. ["elixir", "erlang", "node"]); the
      derived version range is repeated once per flavor with the suffix
      appended (versionType other).
      """

      allow_nil? false
      default []
      public? true
    end

    attribute :versions_override, {:array, :map} do
      description """
      Escape hatch: raw CVE-schema version objects replacing the derived
      versions[] array for this channel.
      """

      public? true
    end

    attribute :entry_override, :map do
      description """
      Escape hatch: RFC 7396 JSON Merge Patch over this channel's rendered
      affected[] entry.
      """

      public? true
    end

    attribute :position, :integer do
      description "Order of this channel among the product's rendered entries."
      allow_nil? false
      default 0
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

    belongs_to :affected_package, Varsel.Cases.AffectedPackage do
      allow_nil? false
      public? true
      attribute_writable? true
    end

    has_many :version_events, Varsel.Cases.VersionEvent do
      public? true
      destination_attribute :package_channel_id
    end
  end

  identities do
    identity :unique_channel, [:affected_package_id, :channel_type, :package_name]
  end
end
