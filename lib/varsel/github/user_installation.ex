# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.GitHub.UserInstallation do
  @moduledoc """
  An installation of the GitHub App that a person's own GitHub token
  reaches, as GitHub last listed it.

  `Varsel.Accounts.User`'s `:sync_github_installations` replaces a person's
  rows. A person without a GitHub identity has no rows.
  """

  use Ash.Resource,
    otp_app: :varsel,
    domain: Varsel.GitHub,
    data_layer: AshPostgres.DataLayer,
    authorizers: [Ash.Policy.Authorizer]

  alias AshOban.Checks.AshObanInteraction
  alias Varsel.Accounts.User
  alias Varsel.GitHub.Installation

  postgres do
    table "github_user_installations"
    repo Varsel.Repo

    references do
      reference :user, on_delete: :delete
      reference :installation, on_delete: :delete
    end
  end

  actions do
    read :read do
      description "Lists which person reaches which installation of the GitHub App."
      primary? true
      public? false
    end

    create :sync do
      description "Stores that a person's GitHub token reaches an installation."
      public? false
      accept [:user_id, :installation_id]
      upsert? true
      upsert_identity :unique_user_installation
      upsert_fields [:synced_at]

      change set_attribute(:synced_at, &DateTime.utc_now/0)
    end

    destroy :forget do
      description "Removes an installation that a person's GitHub token no longer reaches."
      primary? true
      public? false
    end
  end

  policies do
    # Written only by `Varsel.Accounts.User`'s `:sync_github_installations`,
    # which stamps its writes.
    bypass AshObanInteraction do
      authorize_if action_type(:read)
      authorize_if context_equals([:private, :github_sync], true)
    end

    policy action_type(:read) do
      access_type :strict
      authorize_if actor_present()
    end

    policy action_type(:read) do
      authorize_if actor_attribute_equals(:role, :poc)
      authorize_if expr(user_id == ^actor(:id))
    end
  end

  attributes do
    uuid_primary_key :id

    attribute :synced_at, :utc_datetime_usec do
      description "When GitHub last listed the installation for the person."
      allow_nil? false
      public? true
    end

    timestamps()
  end

  relationships do
    belongs_to :user, User do
      allow_nil? false
      public? true
    end

    belongs_to :installation, Installation do
      attribute_type :integer
      allow_nil? false
      public? true
    end
  end

  identities do
    identity :unique_user_installation, [:user_id, :installation_id]
  end
end
