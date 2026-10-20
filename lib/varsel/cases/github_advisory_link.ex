# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.GitHubAdvisoryLink do
  @moduledoc """
  The GitHub security advisory a case is linked to, with the copy of it last
  read from GitHub.

  A case has one advisory and an advisory one case. The copy is what the
  case's GitHub tab sets the case against (`diff`). It is read again on
  request, with the credential `Varsel.GitHub.Credentials` gives the person
  asking, so a draft is visible here exactly when GitHub shows it to that
  credential.

  While the case is open, `:sync_comments` reads the advisory's discussion
  every five minutes and records what it finds as the case's own comments.
  """

  use Ash.Resource,
    otp_app: :varsel,
    domain: Varsel.Cases,
    authorizers: [Ash.Policy.Authorizer],
    data_layer: AshPostgres.DataLayer,
    extensions: [AshOban, AshPaperTrail.Resource],
    notifiers: [Ash.Notifier.PubSub]

  alias AshOban.Checks.AshObanInteraction
  alias Varsel.Cases.Case
  alias Varsel.Cases.GitHubAdvisory.State
  alias Varsel.Cases.GitHubAdvisoryLink.Changes.FetchAdvisory
  alias Varsel.Cases.GitHubAdvisoryLink.Changes.Pull
  alias Varsel.Cases.GitHubAdvisoryLink.Changes.Push
  alias Varsel.Cases.GitHubAdvisoryLink.Changes.StoreAdvisory
  alias Varsel.Cases.GitHubAdvisoryLink.Changes.SyncComments

  postgres do
    table "case_github_advisory_links"
    repo Varsel.Repo

    references do
      reference :case, on_delete: :delete
    end
  end

  oban do
    triggers do
      trigger :sync_comments do
        action :sync_comments

        # Only a case still being worked on, and only a link to a repository
        # advisory: a global database entry has no discussion to read.
        where expr(
                not is_nil(owner) and not is_nil(repo) and
                  case.state in [:draft, :review, :approved] and
                  (is_nil(comments_polled_at) or comments_polled_at < ago(5, :minute))
              )

        worker_module_name Varsel.Cases.GitHubAdvisoryLink.SyncCommentsWorker
        scheduler_module_name Varsel.Cases.GitHubAdvisoryLink.SyncCommentsScheduler
        queue :github_comments
        max_attempts 3
        scheduler_cron "*/5 * * * *"
        worker_opts unique: [period: :infinity, states: :incomplete, keys: [:primary_key]]
      end
    end
  end

  paper_trail do
    change_tracking_mode :changes_only
    reference_source? false
    ignore_attributes [:advisory, :fetched_at, :comments_polled_at, :inserted_at, :updated_at]
    only_when_changed? true
    store_action_name? true
    belongs_to_actor :user, Varsel.Accounts.User, domain: Varsel.Accounts
    version_extensions extensions: [Varsel.Accounts.VersionActorReference]
  end

  actions do
    defaults [:read]

    create :link do
      description """
      Links the case to the advisory at `advisory_url`, read as the caller.
      The rendered record leads its references with the linked advisory,
      tagged vendor-advisory.
      """

      primary? true
      accept [:case_id]

      argument :advisory_url, :string do
        allow_nil? false
        description "The advisory's URL on GitHub, or its GHSA id."
      end

      change FetchAdvisory
      change StoreAdvisory
    end

    create :record do
      description "Internal: records the advisory a case was opened from, or the one GitHub opened for its report."
      accept [:case_id]

      argument :advisory, :map, allow_nil?: false

      change StoreAdvisory
    end

    create :link_attested do
      description """
      Internal: links the case to the advisory a POC read or opened on GitHub
      themselves, as they posted it back for a `Varsel.Cases.GitHubManualRequest`.
      """

      accept [:case_id]

      argument :advisory, :map, allow_nil?: false

      change StoreAdvisory
    end

    update :refresh_attested do
      description """
      Internal: stores the advisory a POC read or wrote on GitHub themselves,
      as they posted it back for a `Varsel.Cases.GitHubManualRequest`.
      """

      accept []
      require_atomic? false

      argument :advisory, :map, allow_nil?: false

      change StoreAdvisory
    end

    update :refresh do
      description "Reads the advisory from GitHub again, as the caller."
      primary? true
      accept []
      require_atomic? false

      change FetchAdvisory
      change StoreAdvisory
    end

    update :sync_comments do
      description """
      Internal: reads the linked advisory's comments and records the ones the
      case does not hold. Run on a schedule, with the App's installation
      token on the advisory's repository.
      """

      public? false

      accept []
      require_atomic? false

      change SyncComments
    end

    update :pull do
      description """
      Takes `fields` of the stored advisory over onto the case, through the
      case's own actions as the caller. A scalar replaces the case's value.
      A set gains what the case lacks and loses nothing.
      """

      accept []
      require_atomic? false

      argument :fields, {:array, :atom} do
        allow_nil? false

        constraints min_length: 1,
                    items: [one_of: [:title, :cvss_v4, :weaknesses, :credits, :affected]]
      end

      change Pull
    end

    update :push do
      description """
      Writes `fields` of the case onto the advisory at GitHub, as the caller,
      and stores the advisory as GitHub then answered. A credit or an affected
      entry the advisory has and the case does not stays on it. People
      credited without a linked GitHub account come back as `skipped_credits`.
      """

      accept []
      require_atomic? false

      argument :fields, {:array, :atom} do
        allow_nil? false

        constraints min_length: 1,
                    items: [
                      one_of: [
                        :title,
                        :description,
                        :cve_id,
                        :cvss_v4,
                        :weaknesses,
                        :credits,
                        :affected
                      ]
                    ]
      end

      metadata :skipped_credits, {:array, :string} do
        description "The names of the people credited here whom the advisory cannot state."
      end

      change Push
      change StoreAdvisory
    end

    destroy :unlink do
      description "Unlinks the advisory."
      primary? true
    end
  end

  policies do
    bypass AshObanInteraction do
      authorize_if action_type(:read)
      authorize_if action(:sync_comments)
    end

    policy action_type(:read) do
      access_type :strict
      authorize_if actor_present()
    end

    policy action_type(:read) do
      authorize_if actor_attribute_equals(:role, :poc)
      authorize_if relates_to_actor_via([:case, :assignments, :user])
    end

    policy action([:link, :unlink, :pull, :push]) do
      authorize_if actor_attribute_equals(:role, :poc)

      authorize_if expr(
                     ^actor(:role) == :supporter and
                       exists(case.assignments, user_id == ^actor(:id))
                   )
    end

    # Content freeze: the link and the case may only change while the case is
    # editable, or when a POC corrects an approved one.
    policy action([:link, :unlink, :pull, :link_attested]) do
      authorize_if expr(case.state in [:draft, :review])

      authorize_if expr(case.state == :approved and ^actor(:role) == :poc)
    end

    policy action(:record) do
      authorize_if accessing_from(Case, :github_advisory_link)
    end

    # Stamped by `Varsel.Cases.GitHubManualRequest.Changes.RecordAnswer`, which
    # records an answer only for the holder of the request's one-time token.
    policy action([:link_attested, :refresh_attested]) do
      forbid_unless context_equals([:private, :github_manual_answer?], true)
      authorize_if actor_attribute_equals(:role, :poc)
    end

    policy action(:refresh) do
      authorize_if actor_attribute_equals(:role, :poc)
      authorize_if relates_to_actor_via([:case, :assignments, :user])
    end

    policy action(:sync_comments) do
      authorize_if AshObanInteraction
      authorize_if actor_attribute_equals(:system, :github_comment_sync)
    end
  end

  pub_sub do
    module VarselWeb.Endpoint
    prefix "case"

    publish_all :create, [[:case_id]]
    publish_all :update, [[:case_id]]
    publish_all :destroy, [[:case_id]]
  end

  attributes do
    uuid_primary_key :id

    attribute :ghsa_id, :string do
      allow_nil? false
      public? true
    end

    attribute :owner, :string do
      description "The repository owner, nil for a global database entry."
      public? true
    end

    attribute :repo, :string do
      description "The repository name, nil for a global database entry."
      public? true
    end

    attribute :html_url, Varsel.Types.URI do
      allow_nil? false
      public? true
    end

    attribute :state, State do
      allow_nil? false
      default :unknown
      public? true
    end

    attribute :title, :string do
      description "The advisory's summary line."
      public? true
    end

    attribute :cve_id, :string do
      description "The CVE ID GitHub shows on the advisory."
      public? true
    end

    attribute :advisory, :map do
      description "The advisory as GitHub last returned it."
      allow_nil? false
      public? false
    end

    attribute :fetched_at, :utc_datetime do
      allow_nil? false
      public? true
    end

    attribute :comments_polled_at, :utc_datetime do
      description "When the advisory's comments were last read. The next read asks GitHub only for what changed since."
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

  calculations do
    calculate :diff, {:array, :map}, Varsel.Cases.GitHubAdvisoryLink.Calculations.Diff do
      description "The case against the advisory, field by field: `Varsel.Cases.GitHubAdvisory.Diff` rows."
      filterable? false
    end
  end

  identities do
    identity :unique_case, [:case_id],
      field_names: [:advisory_url],
      message: "is already linked to an advisory"

    identity :unique_ghsa_id, [:ghsa_id],
      field_names: [:advisory_url],
      message: "is already linked to another case"
  end
end
