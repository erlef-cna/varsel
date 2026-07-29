# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Accounts.UserIdentity.Changes.ReconcileUserNotificationEmail do
  @moduledoc """
  Keeps the account's notification email attested after an identity changes.

  The address a user chose (`:set_notification_email`) was valid because a
  linked provider reported it. Providers change and disappear: an upsert may
  rewrite an identity's email to whatever the provider says now, and an unlink
  removes the identity outright. Either can leave `notification_email` backed
  by nothing — mail would keep going to an address nobody attests any more,
  and the stale value would squat on `unique_notification_email` against
  whoever legitimately holds it next.

  So, in the same transaction as the identity write: if the notification email
  is still reported by at least one linked identity (case-insensitively), do
  nothing — the user's choice stands. Otherwise fall back to the identity
  just written, when it reports an address, else the alphabetically first
  address any remaining identity reports, else nil. Preferring the identity
  just written is "follow the provider": every identity mutation reconciles,
  so a stale address discovered during an upsert was made stale *by* that
  upsert, and the freshly reported address is the same choice, updated.

  The fallback may collide with another account's `notification_email` — their
  own stale claim on an address this user's provider now reports. That is
  pre-checked rather than rescued: a unique violation would poison the
  surrounding sign-in transaction, so on a taken address the fallback is nil.
  The read-then-write race that leaves open fails that one sign-in attempt,
  which a retry resolves.

  All reads and the write here stamp `accessing_from` provenance
  (`UserIdentity.user`), which is what the `Varsel.Accounts.User` policies
  admit them by — the same pattern the catalog syncs use for their join rows.
  """

  use Ash.Resource.Change

  alias Ash.Changeset
  alias Varsel.Accounts.User

  require Ash.Query

  @provenance %{accessing_from: %{source: Varsel.Accounts.UserIdentity, name: :user}}

  @impl Ash.Resource.Change
  def change(changeset, _opts, context) do
    Changeset.after_action(changeset, fn changeset, record ->
      reconcile(record, changeset.action.type, context)
      {:ok, record}
    end)
  end

  defp reconcile(record, action_type, context) do
    opts = Ash.Context.to_opts(context)

    user =
      User
      |> Ash.Query.set_context(@provenance)
      |> Ash.Query.filter(id == ^record.user_id)
      |> Ash.Query.load(:identity_emails)
      |> Ash.read_one!(opts)

    emails = Enum.reject(user.identity_emails || [], &is_nil/1)

    if covered?(user.notification_email, emails) do
      :ok
    else
      candidate =
        record
        |> preferred_email(action_type)
        |> candidate(emails)
        |> available(user, opts)

      Varsel.Accounts.reconcile_user_notification_email!(
        user,
        %{notification_email: candidate},
        Keyword.put(opts, :context, @provenance)
      )

      :ok
    end
  end

  # A destroyed identity attests nothing; on an upsert, what the provider just
  # reported (possibly nil).
  defp preferred_email(_record, :destroy), do: nil
  defp preferred_email(record, _action_type), do: record.email && to_string(record.email)

  # nil means "no address at all", which nothing needs to attest; sign-ins
  # seed it when a provider first reports one (`SeedNotificationEmail`).
  defp covered?(nil, _emails), do: true

  defp covered?(notification_email, emails) do
    Enum.any?(emails, &same_address?(&1, notification_email))
  end

  defp same_address?(a, b), do: String.downcase(to_string(a)) == String.downcase(to_string(b))

  defp candidate(nil, emails), do: emails |> Enum.sort_by(&String.downcase/1) |> List.first()
  defp candidate(preferred, _emails), do: preferred

  defp available(nil, _user, _opts), do: nil

  defp available(candidate, user, opts) do
    taken? =
      User
      |> Ash.Query.set_context(@provenance)
      |> Ash.Query.filter(notification_email == ^candidate and id != ^user.id)
      |> Ash.exists?(opts)

    if taken?, do: nil, else: candidate
  end
end
