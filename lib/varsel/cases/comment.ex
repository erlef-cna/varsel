# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Comment do
  @moduledoc """
  One comment in a case's flat, append-only discussion stream.

  A comment may optionally reference a proposal (review discussion); the
  stream itself always belongs to the case. A comment's text is never edited
  and a comment is never removed: the only update names who wrote it.
  Commenting stays allowed in every case state, including `:closed`
  (post-mortem notes).

  A comment carries the `source` it was written at. A `:github` comment was
  read from the case's linked advisory by `Varsel.Cases.GitHubAdvisoryLink`'s
  comment poll, which names its GitHub author by login. Such a comment also
  carries the `author` whose GitHub identity holds that login, named when the
  poll stores it or when they link the identity later.
  """

  use Ash.Resource,
    otp_app: :varsel,
    domain: Varsel.Cases,
    authorizers: [Ash.Policy.Authorizer],
    data_layer: AshPostgres.DataLayer,
    extensions: [AshPaperTrail.Resource, AshGraphql.Resource],
    notifiers: [Varsel.Notifications.Notifier, Ash.Notifier.PubSub]

  alias AshOban.Checks.AshObanInteraction
  alias Varsel.Accounts.Signals
  alias Varsel.Accounts.User
  alias Varsel.Cases.Comment.Changes.ResolveGitHubAuthor
  alias Varsel.Cases.Comment.Source

  graphql do
    type :case_comment
  end

  postgres do
    table "case_comments"
    repo Varsel.Repo

    references do
      reference :case, on_delete: :delete
      reference :proposal, on_delete: :nilify
      reference :author, on_delete: :nilify
    end

    custom_indexes do
      index [:case_id, :inserted_at]
    end
  end

  paper_trail do
    change_tracking_mode :changes_only
    reference_source? false
    ignore_attributes []
    only_when_changed? true
    store_action_name? true
    belongs_to_actor :user, User, domain: Varsel.Accounts
    version_extensions extensions: [Varsel.Accounts.VersionActorReference]
  end

  actions do
    defaults [:read]

    read :list_for_case do
      description "The case's comment stream, oldest first."
      argument :case_id, :uuid, allow_nil?: false
      filter expr(case_id == ^arg(:case_id))
      prepare build(sort: [inserted_at: :asc])
    end

    create :post do
      description "Posts a comment on a case, optionally referencing one of its proposals."
      primary? true
      accept [:case_id, :proposal_id, :body]

      change relate_actor(:author)
      validate Varsel.Cases.Comment.Validations.ProposalBelongsToCase
    end

    create :sync_from_github do
      description """
      Internal: records one comment read from the case's linked GitHub
      advisory. Keyed on the GitHub comment id, so re-reading a comment the
      poll already stored updates its body instead of repeating it.
      """

      public? false

      accept [:case_id, :body, :github_comment_id, :github_author_login, :github_html_url]

      upsert? true
      upsert_identity :unique_github_comment
      upsert_fields [:body]

      # GitHub answers `since` inclusively, so each poll re-reads the comment
      # it read last. Writing only a body that differs is what keeps a
      # re-read from raising the case's people a second time.
      upsert_condition expr(body != ^atomic_ref(:body))
      return_skipped_upsert? true

      change set_attribute(:source, :github)
      change ResolveGitHubAuthor
    end

    update :claim_for_identity do
      description "Internal: names the account that linked the GitHub login a comment was written by."
      public? false
      accept [:author_id]
      require_atomic? false
    end

    read :for_github_login do
      description "Internal: unclaimed GitHub comments written by a login, for the sign-in claim."
      public? false

      argument :strategy, :string, allow_nil?: false
      argument :username, :string, allow_nil?: false

      filter expr(
               ^arg(:strategy) == "github" and source == :github and is_nil(author_id) and
                 fragment("lower(?) = lower(?)", github_author_login, ^arg(:username))
             )

      pagination keyset?: true, required?: false
    end
  end

  policies do
    bypass action(:claim_for_identity) do
      authorize_if signal_in(Signals, :identity_linked)
    end

    policy action(:sync_from_github) do
      authorize_if actor_attribute_equals(:system, :github_comment_sync)
      authorize_if AshObanInteraction
    end

    policy action([:read, :list_for_case, :post, :for_github_login]) do
      authorize_if signal_in(Signals, :identity_linked)
      authorize_if actor_attribute_equals(:role, :poc)
      authorize_if relates_to_actor_via([:case, :assignments, :user])
    end
  end

  pub_sub do
    module VarselWeb.Endpoint
    prefix "case_comment"

    publish_all :create, [[:case_id]]
  end

  # Append-only: comments are never edited, so create_timestamp :inserted_at is
  # the only meaningful timestamp; an updated_at would always equal it.
  # credo:disable-for-next-line AshCredo.Check.Design.MissingTimestamps
  attributes do
    uuid_primary_key :id

    attribute :body, :string do
      description "Markdown comment body."
      allow_nil? false
      constraints max_length: 20_000
      public? true
    end

    attribute :source, Source do
      description "Where the comment was written."
      allow_nil? false
      default :varsel
      public? true
    end

    attribute :github_comment_id, :integer do
      description "The id GitHub gave the comment, for a comment read from an advisory."
      public? true
    end

    attribute :github_author_login, :string do
      description "The GitHub login that wrote the comment, for a comment read from an advisory."
      public? true
    end

    attribute :github_html_url, Varsel.Types.URI do
      description "The comment's address on GitHub, for a comment read from an advisory."
      public? true
    end

    create_timestamp :inserted_at
  end

  relationships do
    belongs_to :case, Varsel.Cases.Case do
      allow_nil? false
      public? true
      attribute_writable? true
    end

    # Nullable so the comment outlives its author: deleting an account must not
    # take the discussion with it. A nil author renders as a deleted user,
    # except on a `:github` comment, which names its GitHub login instead.
    belongs_to :author, User do
      description """
      Who wrote the comment. Set from the actor, or from the account holding
      the GitHub login for a comment read from an advisory. Nil once they
      delete their account.
      """

      allow_nil? true
      public? true
      attribute_writable? true
    end

    belongs_to :proposal, Varsel.Cases.Proposal do
      description "The proposal this comment discusses, if any."
      allow_nil? true
      public? true
      attribute_writable? true
    end
  end

  signals_in do
    from Signals do
      on :identity_linked, :claim_for_identity,
        read_action: :for_github_login,
        args: [:strategy, :username],
        inputs: [author_id: :user_id]
    end
  end

  identities do
    identity :unique_github_comment, [:github_comment_id],
      nils_distinct?: true,
      message: "is already recorded"
  end
end
