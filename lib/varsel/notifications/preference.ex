# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Notifications.Preference do
  @moduledoc """
  One kind's in-app/email opt-in, embedded in `notification_preferences` on
  `Varsel.Accounts.User`.

  A kind absent from the list defaults to both channels on (`for_kind/2`), so
  a fresh account needs no seeded rows and a new kind is on for everyone
  without a migration.
  """

  use Ash.Resource, data_layer: :embedded, extensions: [AshGraphql.Resource]

  alias Varsel.Notifications.Kind

  @type t :: %__MODULE__{}

  graphql do
    type :notification_preference
  end

  attributes do
    attribute :kind, Kind do
      description "The event kind this preference applies to."
      allow_nil? false
      public? true
    end

    attribute :in_app, :boolean do
      description "Whether this kind shows in the bell and the notifications page."
      allow_nil? false
      default true
      public? true
    end

    attribute :email, :boolean do
      description "Whether this kind requests a notification email."
      allow_nil? false
      default true
      public? true
    end
  end

  @doc """
  Finds `kind`'s preference in `preferences`, defaulting to both channels on
  when the list carries no entry for it.
  """
  @spec for_kind([t()], Kind.t()) :: t()
  def for_kind(preferences, kind) do
    Enum.find(
      preferences,
      struct(__MODULE__, kind: kind, in_app: true, email: true),
      fn preference -> preference.kind == kind end
    )
  end
end
