# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.CaseInvite.Changes.ResolveContact do
  @moduledoc """
  Confirms an invited handle at its provider, stores the spelling it gave
  back, and picks the address the invite email goes to.

  An unconfirmed handle would become an invite nobody can claim, so a provider
  that cannot be reached fails the invite too.
  """

  use Ash.Resource.Change

  import Varsel.Accounts.HandleLookup, only: [provider_name: 1]

  alias Ash.Changeset
  alias Varsel.Accounts.HandleLookup
  alias Varsel.Cases.CaseInvite

  require Ash.Query

  @impl Ash.Resource.Change
  def change(changeset, _opts, context) do
    Changeset.before_action(changeset, fn changeset ->
      strategy = Changeset.get_attribute(changeset, :strategy)
      username = changeset |> Changeset.get_attribute(:username) |> to_string() |> String.trim()
      given = changeset |> Changeset.get_argument(:email) |> blank_to_nil()
      skip? = Changeset.get_argument(changeset, :skip_email) == true
      optional? = Changeset.get_argument(changeset, :email_optional) == true

      with :ok <- present(username),
           {:ok, canonical, provider_email} <- lookup(strategy, username),
           {:ok, email, status} <- decide(strategy, provider_email, given, skip?, optional?) do
        {email, status} = deduplicate(changeset, email, status, context)

        changeset
        |> Changeset.change_attribute(:username, canonical)
        |> Changeset.change_attribute(:email, email)
        |> Changeset.change_attribute(:email_status, status)
      else
        {:error, field, message} -> Changeset.add_error(changeset, field: field, message: message)
      end
    end)
  end

  defp present(""), do: {:error, :username, "is required"}
  defp present(_username), do: :ok

  defp lookup(strategy, username) do
    case HandleLookup.confirm(strategy, username) do
      {:ok, %{username: canonical, email: email}} -> {:ok, canonical, email}
      {:error, message} -> {:error, :username, message}
    end
  end

  defp decide(_strategy, nil, nil, true, _optional?), do: {:ok, nil, :skipped}
  defp decide(_strategy, nil, nil, false, true), do: {:ok, nil, :skipped}

  defp decide(strategy, nil, nil, false, false) do
    {:error, :email,
     "is needed: #{provider_name(strategy)} lists no address for this account. Enter one, or skip the email."}
  end

  defp decide(_strategy, nil, _given, true, _optional?) do
    {:error, :skip_email, "cannot be set together with an email"}
  end

  defp decide(_strategy, nil, given, false, _optional?), do: {:ok, given, :pending}

  defp decide(strategy, _provider_email, _given, true, _optional?) do
    {:error, :skip_email, "#{provider_name(strategy)} lists an address for this account, so the email cannot be skipped"}
  end

  defp decide(strategy, provider_email, given, false, _optional?) do
    if is_nil(given) or same_address?(given, provider_email) do
      {:ok, provider_email, :pending}
    else
      {:error, :email, "does not match the address #{provider_name(strategy)} lists for this account"}
    end
  end

  defp deduplicate(changeset, email, :pending, context) do
    case_id = Changeset.get_attribute(changeset, :case_id)

    emailed? =
      CaseInvite
      |> Ash.Query.filter(case_id == ^case_id and email == ^email and email_status in [:pending, :sent])
      |> Ash.exists?(Ash.Context.to_opts(context))

    if emailed?, do: {email, :duplicate}, else: {email, :pending}
  end

  defp deduplicate(_changeset, email, status, _context), do: {email, status}

  defp same_address?(left, right), do: String.downcase(left) == String.downcase(right)

  defp blank_to_nil(nil), do: nil

  defp blank_to_nil(value) do
    case String.trim(value) do
      "" -> nil
      trimmed -> trimmed
    end
  end
end
