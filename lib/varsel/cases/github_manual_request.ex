# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.GitHubManualRequest do
  @moduledoc """
  A GitHub request that a POC makes from their own machine with `gh`, where
  no credential Varsel holds reaches the repository: the App is not installed
  on it.

  The row holds the request that the automatic action would have made. The
  POC runs one command. The command fetches the request from
  `/api/github/manual/:id/request`, sends it to GitHub with `gh api`, and
  posts GitHub's answer to `/api/github/manual/:id/result`. A one-time
  AshAuthentication token of purpose `github_manual`, minted for the POC,
  authorizes those two steps. The answer is then recorded as the POC, the way
  the automatic action records its own.

  The request belongs to its token's row in `Varsel.Accounts.Token`. The
  token expunger deletes that row once the token has expired, and the request
  goes with it.
  """

  use Ash.Resource,
    otp_app: :varsel,
    domain: Varsel.Cases,
    authorizers: [Ash.Policy.Authorizer],
    data_layer: AshPostgres.DataLayer

  alias Varsel.Cases.GitHubManualRequest.Changes.BuildRequest
  alias Varsel.Cases.GitHubManualRequest.Changes.MintToken
  alias Varsel.Cases.GitHubManualRequest.Changes.RecordAnswer
  alias Varsel.Cases.GitHubManualRequest.Checks.MayRunAction
  alias Varsel.Cases.GitHubManualRequest.Checks.TokenMatches
  alias Varsel.Cases.GitHubManualRequest.Operation
  alias Varsel.Cases.GitHubManualRequest.Validations.AnswerNamesRequest

  @pullable [:title, :cvss_v4, :weaknesses, :credits, :affected]
  @pushable [:title, :description, :cve_id, :cvss_v4, :weaknesses, :credits, :affected]

  postgres do
    table "github_manual_requests"
    repo Varsel.Repo

    references do
      reference :case, on_delete: :delete
      reference :user, on_delete: :delete
      reference :token, on_delete: :delete
    end
  end

  actions do
    read :read do
      description "The manual requests of the acting user."
      primary? true
    end

    read :locate do
      description "Finds a request by its id, for the two steps that the token then authorizes."
    end

    create :prepare_link do
      description "Prepares the read of the advisory at `advisory_url`, which the answer then links to the case."
      primary? true
      accept [:case_id]

      argument :advisory_url, :string do
        allow_nil? false
        description "The advisory's URL on GitHub."
      end

      metadata :token, :string, description: "The one-time token, given here and nowhere else."

      change relate_actor(:user)
      change BuildRequest
      change MintToken
    end

    create :prepare_refresh do
      description "Prepares a new read of the linked advisory."

      argument :link_id, :uuid, allow_nil?: false

      metadata :token, :string, description: "The one-time token, given here and nowhere else."

      change relate_actor(:user)
      change BuildRequest
      change MintToken
    end

    create :prepare_pull do
      description "Prepares a new read of the linked advisory, after which `fields` are pulled onto the case."

      argument :link_id, :uuid, allow_nil?: false

      argument :fields, {:array, :atom} do
        allow_nil? false
        constraints min_length: 1, items: [one_of: @pullable]
      end

      metadata :token, :string, description: "The one-time token, given here and nowhere else."

      change relate_actor(:user)
      change BuildRequest
      change MintToken
    end

    create :prepare_push do
      description "Prepares the write of `fields` of the case onto the linked advisory."

      argument :link_id, :uuid, allow_nil?: false

      argument :fields, {:array, :atom} do
        allow_nil? false
        constraints min_length: 1, items: [one_of: @pushable]
      end

      metadata :token, :string, description: "The one-time token, given here and nowhere else."

      change relate_actor(:user)
      change BuildRequest
      change MintToken
    end

    create :prepare_report do
      description """
      Prepares a draft advisory (`draft`, for a person who administers the
      repository) or a private report on `owner/repo`, with what the case
      states and `description`.
      """

      accept [:case_id]

      argument :owner, :string, allow_nil?: false
      argument :repo, :string, allow_nil?: false

      argument :description, :string do
        allow_nil? false
        constraints max_length: 65_535
      end

      argument :draft, :boolean, allow_nil?: false, default: true

      metadata :token, :string, description: "The one-time token, given here and nowhere else."

      change relate_actor(:user)
      change BuildRequest
      change MintToken
    end

    update :fetch do
      description "Answers the request to send to GitHub, to the holder of the token."
      primary? true
      accept []

      argument :token, :string do
        allow_nil? false
        sensitive? true
      end

      change filter(expr(is_nil(completed_at)))
      change set_attribute(:fetched_at, &DateTime.utc_now/0)
    end

    update :complete do
      description "Records GitHub's answer, posted by the holder of the token, and revokes the token."
      accept []
      require_atomic? false

      argument :token, :string do
        allow_nil? false
        sensitive? true
      end

      argument :answer, :map, allow_nil?: false

      validate AnswerNamesRequest, before_action?: true

      change filter(expr(is_nil(completed_at)))
      change set_attribute(:completed_at, &DateTime.utc_now/0)
      change RecordAnswer
    end
  end

  policies do
    policy action(:read) do
      access_type :strict
      authorize_if actor_present()
    end

    policy action(:read) do
      authorize_if relates_to_actor_via(:user)
    end

    policy action(:locate) do
      access_type :strict
      authorize_if actor_attribute_equals(:system, :github_manual)
    end

    policy action([
             :prepare_link,
             :prepare_refresh,
             :prepare_pull,
             :prepare_push,
             :prepare_report
           ]) do
      forbid_unless actor_attribute_equals(:role, :poc)
      authorize_if MayRunAction
    end

    policy action([:fetch, :complete]) do
      authorize_if TokenMatches
    end
  end

  attributes do
    uuid_primary_key :id

    attribute :operation, Operation do
      allow_nil? false
      public? true
    end

    attribute :method, :atom do
      allow_nil? false
      constraints one_of: [:get, :patch, :post]
      public? true
    end

    attribute :path, :string do
      description "The GitHub API path the command calls."
      allow_nil? false
      public? true
    end

    attribute :body, :map do
      description "The JSON the command sends to GitHub. nil for a read."
      public? true
    end

    attribute :fields, {:array, :atom} do
      description "The fields a pull takes over or a push writes. nil otherwise."
      public? true
    end

    attribute :advisory_url, :string do
      description "The advisory address pasted into the link form, for a read that links."
      public? true
    end

    attribute :owner, :string, allow_nil?: false, public?: true
    attribute :repo, :string, allow_nil?: false, public?: true

    attribute :ghsa_id, :string do
      description "The advisory the answer must be. nil for a report."
      public? true
    end

    attribute :fetched_at, :utc_datetime_usec, public?: true
    attribute :completed_at, :utc_datetime_usec, public?: true

    timestamps()
  end

  relationships do
    belongs_to :case, Varsel.Cases.Case do
      allow_nil? false
      public? true
      attribute_writable? true
    end

    belongs_to :user, Varsel.Accounts.User do
      description "The POC who prepared the request, as whom its answer is recorded."
      allow_nil? false
    end

    belongs_to :token, Varsel.Accounts.Token do
      description "The row of the request's one-time token."
      attribute_type :string
      destination_attribute :jti
      allow_nil? false
    end
  end
end
