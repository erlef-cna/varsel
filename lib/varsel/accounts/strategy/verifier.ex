# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Accounts.Strategy.Verifier do
  @moduledoc """
  Runs AshAuthentication's OAuth2 strategy verification, minus its
  unverified-email warning.

  That warning fires whenever `trust_email_verified?` is false and no
  confirmation add-on is configured, on the premise that an account would
  otherwise carry an email nobody has proven ownership of. Here the premise
  does not lead anywhere: an email is a notification address only, never an
  authentication factor and never a way to reach an account (see the `:email`
  attribute on `Varsel.Accounts.User`). Both providers deliberately keep
  `trust_email_verified? false` precisely so that a matching address can never
  link a sign-in to an existing account, which is the behaviour the warning
  would have us trade away.

  Every hard validation still runs; only the warning is dropped.
  """

  alias AshAuthentication.Strategy.OAuth2.Verifier

  @doc false
  @spec verify(struct, map) :: :ok | {:error, Exception.t()} | {:warn, [String.t()]}
  # `Verifier.verify/2` ends in `oauth2_strategy_warnings/2` and does return
  # `{:warn, _}`, but its upstream spec omits that, so Dialyzer reads the
  # clause below as unreachable.
  @dialyzer {:nowarn_function, verify: 2}
  def verify(strategy, dsl_state) do
    case Verifier.verify(strategy, dsl_state) do
      {:warn, warnings} ->
        case Enum.reject(warnings, &unverified_email_warning?/1) do
          [] -> :ok
          remaining -> {:warn, remaining}
        end

      other ->
        other
    end
  end

  defp unverified_email_warning?(warning),
    do: String.contains?(warning, "does not trust the provider's `email_verified` claim")
end
