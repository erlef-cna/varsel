# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.PackageChannel do
  @moduledoc """
  One distribution channel of a `Varsel.Cases.AffectedPackage` — rendered as
  exactly one `affected[]` entry in the CNA container.

  A channel is one of two `kind`s:

  * `:package` — identified by a Package URL, authored as its parts (`purl_type`
    + `namespace` / `name` / `qualifiers` / `subpath`). Any purl type works:
    the type is an open string, and `Varsel.Cases.PackageChannel.PurlType`
    supplies the conventions of the ones we know without restricting the rest.
    The source repository is a channel like any other (`pkg:github/...`, or
    `pkg:generic` for an unregistered forge), derived from the package's
    `repo_url` when it is added.
  * `:service` — a running service with no package to download, identified by
    the `domain` it answers on and versioned by date.

  Version boundaries come from the package's `Varsel.Cases.VersionEvent` facts,
  resolved per channel by `Varsel.Cases.Derivation` and written in the
  channel's `version_type` vocabulary.

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
    extensions: [AshPaperTrail.Resource, AshGraphql.Resource],
    notifiers: [Ash.Notifier.PubSub]

  alias Varsel.Cases.Changes.ApplyProposedField
  alias Varsel.Cases.Changes.SupersedeOrphanedProposals
  alias Varsel.Cases.PackageChannel.Calculations.Purl, as: PurlCalculation
  alias Varsel.Cases.PackageChannel.Kind
  alias Varsel.Cases.PackageChannel.PurlType
  alias Varsel.Cases.PackageChannel.Validations.ConsistentIdentity
  alias Varsel.Cases.PackageChannel.Validations.ConsistentWithPackage
  alias Varsel.Cases.PackageChannel.VersionType
  alias Varsel.Cases.Proposable

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
    version_extensions extensions: [Varsel.Accounts.VersionActorReference]
  end

  actions do
    defaults [:read]

    create :add do
      primary? true
      description "Adds a distribution channel to a logical product."
      accept [:case_id, :affected_package_id | Proposable.fields(__MODULE__)]
      validate ConsistentWithPackage
    end

    update :edit do
      primary? true
      description "Edits a channel. Only allowed while the case is editable."
      accept Proposable.fields(__MODULE__)
      require_atomic? false
      validate ConsistentWithPackage
    end

    destroy :remove do
      primary? true
      description "Removes a channel from a logical product."
      require_atomic? false
      change SupersedeOrphanedProposals
    end

    update :apply_proposal do
      description "Internal: applies one accepted proposal value to a single field."
      accept []
      require_atomic? false

      argument :field, :string, allow_nil?: false
      argument :value, :term
      argument :proposal_id, :uuid, allow_nil?: false
      validate ConsistentWithPackage
      change ApplyProposedField
    end

    create :apply_proposal_insert do
      description "Internal: creates the row proposed by an accepted :insert proposal."
      accept [:case_id, :affected_package_id | Proposable.fields(__MODULE__)]

      argument :proposal_id, :uuid, allow_nil?: false
      validate ConsistentWithPackage
    end

    destroy :apply_proposal_delete do
      description "Internal: removes the row targeted by an accepted :delete proposal."
      require_atomic? false

      argument :proposal_id, :uuid, allow_nil?: false
      change SupersedeOrphanedProposals
    end
  end

  policies do
    policy action_type(:read) do
      authorize_if actor_attribute_equals(:role, :poc)
      authorize_if relates_to_actor_via([:case, :assignments, :user])
    end

    # Writing a case's facts is editing the case, so it needs a role as
    # well as an assignment — an assigned collaborator proposes instead.
    policy action_type([:create, :update, :destroy]) do
      authorize_if actor_attribute_equals(:role, :poc)

      authorize_if expr(
                     ^actor(:role) == :supporter and
                       exists(case.assignments, user_id == ^actor(:id))
                   )
    end

    # Content freeze: child rows may only change while the parent case is editable.
    policy action_type([:create, :update, :destroy]) do
      authorize_if expr(case.state in [:draft, :review])
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
    validate ConsistentIdentity, on: [:create, :update]
  end

  attributes do
    uuid_primary_key :id

    attribute :kind, Kind do
      description """
      Whether this channel distributes a package (purl-identified) or is a
      running service (domain-identified, versioned by date).
      """

      allow_nil? false
      default :package
      public? true
    end

    attribute :purl_type, PurlType do
      description """
      Package URL type, e.g. "hex", "npm", "oci", "otp", "github", "cargo".
      Any purl type is accepted; the well-known ones additionally supply a
      collectionURL and a default versionType. Nil for :service channels.
      """

      public? true
    end

    attribute :namespace, :string do
      description """
      The purl namespace, e.g. "gleam.run" (sid), "erlang" (github) or an npm
      scope. Nil for unnamespaced ecosystems like hex.
      """

      public? true
    end

    attribute :name, :string do
      description """
      The purl name, e.g. "ash_authentication_phoenix" (hex), "stdlib" (otp),
      "otp" (github). Required for :package channels.
      """

      public? true
    end

    attribute :domain, :string do
      description """
      The domain a :service channel answers on, e.g. "hex.pm". Identifies the
      service in place of a purl; nil for :package channels.
      """

      public? true
    end

    attribute :qualifiers, :map do
      description """
      Purl qualifiers rendered into the packageURL, e.g.
      %{"repository_url" => "ghcr.io/gleam-lang"} for oci, or vcs_url on the
      repository channel of a forge with no purl type of its own.
      """

      allow_nil? false
      default %{}
      public? true
    end

    attribute :subpath, :string do
      description """
      Repository-root-relative directory this channel distributes, e.g.
      "lib/ssh" for pkg:otp/ssh or "erts" for pkg:otp/erts. The rendered
      entry's programFiles (and the modules/routines they contribute) are
      scoped to files under it, paths relative to it. Nil distributes the
      whole repository.
      """

      public? true
    end

    attribute :version_type, VersionType do
      description """
      Vocabulary the derived version bounds are written in. Nil takes the purl
      type's default (hex/npm semver, otp otp, oci other, github/generic git);
      :service channels are always date.
      """

      public? true
    end

    attribute :tag_prefix, :string do
      description """
      String prepended to every derived version, e.g. "v" for `v1.2.3` tags.
      Nil or empty for bare versions.
      """

      public? true
    end

    attribute :tag_suffixes, {:array, :string} do
      description """
      Flavor suffixes appended to every derived version (e.g. ["elixir",
      "erlang", "node"] for an image published once per runtime); the derived
      range repeats once per flavor. A "-" entry is the bare version, so a
      channel publishing both 1.2.3 and 1.2.3-special uses ["-", "special"].
      Empty renders the version alone.
      """

      allow_nil? false
      default []
      public? true
    end

    attribute :versions_override, Varsel.Types.JsonObjectList do
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

  calculations do
    calculate :purl, :string, PurlCalculation do
      description """
      The composed Package URL of this channel, e.g.
      "pkg:hex/ash_authentication_phoenix" or
      "pkg:oci/gleam?repository_url=ghcr.io/gleam-lang". Nil for :service
      channels, which have a domain rather than a purl.
      """

      public? true
    end
  end

  identities do
    identity :unique_channel, [:affected_package_id, :purl_type, :namespace, :name, :domain], nils_distinct?: false
  end
end
