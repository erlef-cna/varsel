# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

# credo:disable-for-this-file AshCredo.Check.Design.MissingCodeInterface
# The primary read and the writes run only inside
# `Varsel.GitHub.UserInstallation.ForActor`.
#
# credo:disable-for-this-file AshCredo.Check.Design.MissingTimestamps
# `fetched_at` is the one time that matters: when GitHub answered.
defmodule Varsel.GitHub.UserInstallation do
  @moduledoc """
  An installation of the GitHub App that a person's own GitHub token
  reaches, as GitHub last answered.

  The rows are a cache that lives in memory on each node. A person who
  reaches no installation has no rows, so each read asks GitHub again.
  """

  use Ash.Resource,
    otp_app: :varsel,
    domain: Varsel.GitHub,
    data_layer: Ash.DataLayer.Ets,
    authorizers: [Ash.Policy.Authorizer]

  alias Varsel.GitHub.UserInstallation.ForActor

  ets do
    private? Mix.env() == :test
  end

  actions do
    read :read do
      description "The actor's cached rows."
      primary? true
      public? false
    end

    read :for_actor do
      description "The installations of the App that the actor's own GitHub token reaches."
      public? false

      manual ForActor
    end

    create :store do
      description "Stores that the actor's GitHub token reaches an installation."
      public? false
      accept [:installation_id, :fetched_at]

      change set_attribute(:user_id, actor(:id))
      change set_new_attribute(:fetched_at, &DateTime.utc_now/0)
    end

    destroy :forget do
      description "Forgets one of the actor's rows."
      public? false
    end
  end

  policies do
    policy action_type(:read) do
      access_type :strict
      authorize_if actor_present()
    end

    policy action_type(:read) do
      authorize_if expr(user_id == ^actor(:id))
    end

    # Stamped by ForActor.
    policy action_type(:create) do
      forbid_unless context_equals([:private, :installation_sync], true)
      authorize_if actor_present()
    end

    policy action_type(:destroy) do
      forbid_unless context_equals([:private, :installation_sync], true)
      authorize_if expr(user_id == ^actor(:id))
    end
  end

  attributes do
    attribute :user_id, :uuid do
      primary_key? true
      allow_nil? false
      public? true
    end

    attribute :installation_id, :integer do
      primary_key? true
      allow_nil? false
      public? true
    end

    attribute :fetched_at, :utc_datetime_usec do
      allow_nil? false
      public? true
    end
  end
end
