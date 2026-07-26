# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

# Answers a refused policy with 401 rather than 403 when signing in is what
# would fix it.

# A policy refusal means one of two different things, and the two want
# different pages: an account that may not do this (403 — the page explains
# which roles can, and how to ask), or nobody being signed in at all (401 —
# the page offers a way in). Telling them apart is a matter of reading the
# breakdown Ash already attaches: the actor is nil, and the presence check is
# among the facts that came back false.

# `ash_phoenix` maps this error to a flat 403, so `:exclude_exceptions_from_plug`
# hands it here instead.
defimpl Plug.Exception, for: Ash.Error.Forbidden.Policy do
  def status(%{actor: nil} = error) do
    if failed_on_presence?(error), do: 401, else: 403
  end

  def status(_error), do: 403

  def actions(_error), do: []

  defp failed_on_presence?(%{facts: facts}) when is_map(facts) do
    Enum.any?(facts, fn
      {{Ash.Policy.Check.ActorPresent, _opts}, false} -> true
      _fact -> false
    end)
  end

  defp failed_on_presence?(_error), do: false
end
