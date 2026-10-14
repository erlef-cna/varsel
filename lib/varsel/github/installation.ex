# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

# credo:disable-for-this-file AshCredo.Check.Design.MissingCodeInterface
# The primary read and the cache writes run only inside the lookups and
# `Varsel.GitHub.Installation.Mint`.
#
# credo:disable-for-this-file AshCredo.Check.Design.MissingTimestamps
# `fetched_at` is the one time that matters: when GitHub answered.
defmodule Varsel.GitHub.Installation do
  @moduledoc """
  An installation of the GitHub App that GitHub answered about, and the
  installation token last minted for it.

  The rows are a cache that lives in memory on each node. A missing row
  says only that nobody asked yet. `Varsel.GitHub.InstallationLookup`
  records which installation covers a repository or an organization.
  """

  use Ash.Resource,
    otp_app: :varsel,
    domain: Varsel.GitHub,
    data_layer: Ash.DataLayer.Ets,
    authorizers: [Ash.Policy.Authorizer]

  alias Varsel.GitHub.Installation.Actions.PublicReadToken
  alias Varsel.GitHub.Installation.Actions.Token
  alias Varsel.GitHub.Installation.Lookup

  ets do
    private? Mix.env() == :test
  end

  field_policies do
    field_policy [:token, :token_expires_at] do
      authorize_if actor_attribute_equals(:role, :poc)
      authorize_if actor_attribute_equals(:system, :github_public_read)
    end

    field_policy :* do
      authorize_if always()
    end
  end

  actions do
    read :read do
      description "The cached installations."
      primary? true
      public? false
    end

    read :for_repository do
      description "The installation of the App that covers the repository `owner/repo`."
      public? false

      argument :owner, :string do
        allow_nil? false
        constraints match: ~r/\A[^\/]+\z/
      end

      argument :repo, :string do
        allow_nil? false
        constraints match: ~r/\A[^\/]+\z/
      end

      manual {Lookup, scope: :repository}
    end

    read :for_org do
      description "The installation of the App on the organization `account`."
      public? false

      argument :account, :string do
        allow_nil? false
        constraints match: ~r/\A[^\/]+\z/
      end

      manual {Lookup, scope: :org}
    end

    create :store do
      description "Stores an installation as GitHub described it, and keeps its token."
      public? false
      accept [:id, :account, :kind, :repository_selection, :fetched_at]
      upsert? true
      upsert_fields [:account, :kind, :repository_selection, :fetched_at]

      change set_new_attribute(:fetched_at, &DateTime.utc_now/0)
    end

    update :store_token do
      description "Stores a newly minted installation token."
      public? false
      accept [:token, :token_expires_at]
    end

    action :token, :string do
      description """
      Returns an installation token for the installation `installation_id`.
      The token stays valid for at least five more minutes. Only a POC can
      get it.
      """

      public? false

      argument :installation_id, :integer, allow_nil?: false

      run Token
    end

    action :public_read_token, :string do
      description """
      Returns the installation token of the GitHub App on the home
      organization. Anyone can get this token. Use it only for GET requests
      about public data that belongs to nobody in particular: the global
      advisory database, a profile lookup, the OTP versions table. Never use
      it for a request about a specific repository. This rule also applies
      to a repository in the home organization. Never use it for a request
      that is not a GET request.
      """

      public? false

      run PublicReadToken
    end
  end

  policies do
    policy action_type(:read) do
      access_type :strict
      authorize_if actor_present()
    end

    # Stamped by Lookup and Installation.Mint.
    policy action_type([:create, :update]) do
      forbid_unless context_equals([:private, :installation_sync], true)
      authorize_if actor_present()
    end

    policy action(:token) do
      description "Only a POC acts with an installation token. This policy is the one place that rule lives."
      access_type :strict
      authorize_if actor_attribute_equals(:role, :poc)
    end

    policy action(:public_read_token) do
      authorize_if always()
    end
  end

  attributes do
    attribute :id, :integer do
      description "GitHub's id of the installation."
      primary_key? true
      allow_nil? false
      public? true
    end

    attribute :account, :ci_string do
      description "The login of the account the App is installed on."
      allow_nil? false
      public? true
    end

    attribute :kind, :atom do
      constraints one_of: [:organization, :user]
      allow_nil? false
      public? true
    end

    attribute :repository_selection, :atom do
      constraints one_of: [:all, :selected]
      allow_nil? false
      public? true
    end

    attribute :token, :string do
      sensitive? true
      allow_nil? true
      public? true
    end

    attribute :token_expires_at, :utc_datetime_usec do
      allow_nil? true
      public? true
    end

    attribute :fetched_at, :utc_datetime_usec do
      description "When GitHub last described the installation."
      allow_nil? false
      public? true
    end
  end
end
