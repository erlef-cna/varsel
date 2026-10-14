# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

# credo:disable-for-this-file AshCredo.Check.Design.MissingCodeInterface
# The read and the write run only inside `Varsel.GitHub.Installation.Lookup`.
#
# credo:disable-for-this-file AshCredo.Check.Design.MissingTimestamps
# `fetched_at` is the one time that matters: when GitHub answered.
defmodule Varsel.GitHub.InstallationLookup do
  @moduledoc """
  GitHub's last answer to which installation of the App covers a repository
  or an organization, positive or negative.

  `subject` is the key: `owner/repo` for a repository, the login alone for
  an organization, both in lowercase. A GitHub login never contains a slash,
  so the two kinds of key cannot collide. `installation_id` is nil when
  GitHub answered that the App is not installed there.
  `Varsel.GitHub.Installation.Lookup` sets how long an answer stays fresh
  after `fetched_at`.
  """

  use Ash.Resource,
    otp_app: :varsel,
    domain: Varsel.GitHub,
    data_layer: Ash.DataLayer.Ets,
    authorizers: [Ash.Policy.Authorizer]

  ets do
    private? Mix.env() == :test
  end

  actions do
    read :read do
      description "The cached answers."
      primary? true
      public? false
    end

    create :store do
      description "Stores GitHub's answer for a subject, positive or negative."
      public? false
      accept [:subject, :installation_id, :fetched_at]
      upsert? true
      upsert_fields [:installation_id, :fetched_at]

      change set_new_attribute(:fetched_at, &DateTime.utc_now/0)
    end
  end

  policies do
    policy action_type(:read) do
      access_type :strict
      authorize_if actor_present()
    end

    # Stamped by Varsel.GitHub.Installation.Lookup.
    policy action_type(:create) do
      forbid_unless context_equals([:private, :installation_sync], true)
      authorize_if actor_present()
    end
  end

  attributes do
    attribute :subject, :string do
      primary_key? true
      allow_nil? false
      public? true
    end

    attribute :installation_id, :integer do
      allow_nil? true
      public? true
    end

    attribute :fetched_at, :utc_datetime_usec do
      allow_nil? false
      public? true
    end
  end
end
