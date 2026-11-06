# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.CommentReaction do
  @moduledoc """
  One person's emoji reaction to a comment in a case's discussion.

  Whoever may read a case's comments may react to them, a comment read from
  GitHub included, and each person gives a comment each emoji at most once.
  A reaction stays here: it is never written to a linked advisory. Only the
  person who reacted takes a reaction back.
  """

  use Ash.Resource,
    otp_app: :varsel,
    domain: Varsel.Cases,
    authorizers: [Ash.Policy.Authorizer],
    data_layer: AshPostgres.DataLayer,
    notifiers: [Ash.Notifier.PubSub]

  alias Varsel.Accounts.User
  alias Varsel.Cases.CommentReaction.Emoji
  alias Varsel.Cases.CommentReaction.Validations.CommentBelongsToCase

  postgres do
    table "case_comment_reactions"
    repo Varsel.Repo

    references do
      reference :case, on_delete: :delete
      reference :comment, on_delete: :delete
      reference :user, on_delete: :delete
    end
  end

  actions do
    defaults [:read]

    create :react do
      description "Reacts to a comment with an emoji. Reacting again with the same emoji changes nothing."
      primary? true
      accept [:case_id, :comment_id, :emoji]

      upsert? true
      upsert_identity :unique_reaction
      upsert_fields [:emoji]

      change relate_actor(:user)
      validate CommentBelongsToCase, before_action?: true
    end

    destroy :unreact do
      description "Takes back one of the actor's own reactions."
      primary? true
    end
  end

  policies do
    policy action_type(:read) do
      access_type :strict
      authorize_if actor_present()
    end

    policy action_type(:read) do
      authorize_if actor_attribute_equals(:role, :poc)
      authorize_if relates_to_actor_via([:case, :assignments, :user])
    end

    policy action(:react) do
      authorize_if actor_attribute_equals(:role, :poc)
      authorize_if relates_to_actor_via([:case, :assignments, :user])
    end

    policy action(:unreact) do
      authorize_if expr(user_id == ^actor(:id))
    end
  end

  pub_sub do
    module VarselWeb.Endpoint
    prefix "case_comment"

    publish_all :create, [[:case_id]]
    publish_all :destroy, [[:case_id]]
  end

  # A reaction is given or taken back, never edited.
  # credo:disable-for-next-line AshCredo.Check.Design.MissingTimestamps
  attributes do
    uuid_primary_key :id

    attribute :emoji, Emoji do
      description "The emoji reacted with."
      allow_nil? false
      public? true
    end

    create_timestamp :inserted_at
  end

  relationships do
    belongs_to :case, Varsel.Cases.Case do
      description "The case of the comment, which decides who may see and give the reaction."
      allow_nil? false
      public? true
      attribute_writable? true
    end

    belongs_to :comment, Varsel.Cases.Comment do
      description "The comment reacted to."
      allow_nil? false
      public? true
      attribute_writable? true
    end

    belongs_to :user, User do
      description "Who reacted."
      allow_nil? false
      public? true
    end
  end

  identities do
    identity :unique_reaction, [:comment_id, :user_id, :emoji]
  end
end
