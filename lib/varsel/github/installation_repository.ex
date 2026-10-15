# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.GitHub.InstallationRepository do
  @moduledoc """
  A repository that an installation of the GitHub App with
  `repository_selection: :selected` covers, as GitHub last listed it.

  An installation with `repository_selection: :all` has no rows here. It
  covers every repository of its account.
  """

  use Ash.Resource,
    otp_app: :varsel,
    domain: Varsel.GitHub,
    data_layer: AshPostgres.DataLayer,
    authorizers: [Ash.Policy.Authorizer]

  alias AshOban.Checks.AshObanInteraction
  alias Varsel.GitHub.Installation

  postgres do
    table "github_installation_repositories"
    repo Varsel.Repo

    references do
      reference :installation, on_delete: :delete
    end
  end

  actions do
    read :read do
      description "Lists the repositories that selective installations cover."
      primary? true
      public? false
    end

    create :sync do
      description "Stores a repository that GitHub lists for a selective installation."
      public? false
      accept [:installation_id, :owner, :repo]
      upsert? true
      upsert_identity :unique_repository
      upsert_fields [:owner, :repo]
    end

    destroy :forget do
      description "Removes a repository that GitHub no longer lists for its installation."
      primary? true
      public? false
    end
  end

  policies do
    # Written only by `Varsel.GitHub.Installation`'s `:sync_all`, which
    # stamps its writes.
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
      authorize_if expr(exists(installation.user_installations, user_id == ^actor(:id)))
    end

    # Stamped by the person's own `Varsel.Accounts.User`
    # `:sync_github_installations`, which adds what their token lists.
    policy action(:sync) do
      forbid_unless context_equals([:private, :github_sync], true)
      authorize_if actor_present()
    end
  end

  attributes do
    uuid_primary_key :id

    attribute :owner, :ci_string do
      description "The login of the account that owns the repository."
      allow_nil? false
      public? true
    end

    attribute :repo, :ci_string do
      description "The name of the repository, without its owner."
      allow_nil? false
      public? true
    end

    timestamps()
  end

  relationships do
    belongs_to :installation, Installation do
      attribute_type :integer
      allow_nil? false
      public? true
    end
  end

  identities do
    identity :unique_repository, [:installation_id, :owner, :repo]
  end
end
