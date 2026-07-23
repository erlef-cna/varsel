# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Comment do
  @moduledoc """
  One comment in a case's flat, append-only discussion stream.

  A comment may optionally reference a proposal (review discussion); the
  stream itself always belongs to the case. There are deliberately no update
  or destroy actions — immutability by omission. Commenting stays allowed in
  every case state, including `:closed` (post-mortem notes).
  """

  use Ash.Resource,
    otp_app: :varsel,
    domain: Varsel.Cases,
    authorizers: [Ash.Policy.Authorizer],
    data_layer: AshPostgres.DataLayer,
    extensions: [AshPaperTrail.Resource, AshGraphql.Resource],
    notifiers: [Ash.Notifier.PubSub]

  alias Varsel.Accounts.User

  graphql do
    type :case_comment
  end

  postgres do
    table "case_comments"
    repo Varsel.Repo

    references do
      reference :case, on_delete: :delete
      reference :proposal, on_delete: :nilify
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
      accept [:case_id, :proposal_id, :body]

      change relate_actor(:author)
      validate Varsel.Cases.Comment.Validations.ProposalBelongsToCase
    end
  end

  policies do
    policy action_type([:read, :create]) do
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

    create_timestamp :inserted_at
  end

  relationships do
    belongs_to :case, Varsel.Cases.Case do
      allow_nil? false
      public? true
      attribute_writable? true
    end

    belongs_to :author, User do
      description "Who wrote the comment. Set from the actor."
      allow_nil? false
      public? true
    end

    belongs_to :proposal, Varsel.Cases.Proposal do
      description "The proposal this comment discusses, if any."
      allow_nil? true
      public? true
      attribute_writable? true
    end
  end
end
