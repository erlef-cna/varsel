# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Accounts.Strategy.Hex do
  @moduledoc """
  Strategy for authenticating using [Hex.pm](https://hex.pm).

  Builds on `AshAuthentication.Strategy.OAuth2`. Hex.pm is a plain OAuth2
  server rather than an OIDC provider, so the endpoints and profile mapping
  come from `Varsel.Accounts.Assent.Hex`, which documents the consequences.

  Requires `client_id`, `client_secret`, `redirect_uri` and `base_url` — the
  last because hex.pm is self-hostable and local development runs its own.
  """

  use AshAuthentication.Strategy.Custom, entity: __MODULE__.Dsl.dsl()

  alias AshAuthentication.Strategy.OAuth2
  alias Varsel.Accounts.Strategy.Verifier

  defdelegate transform(strategy, dsl_state), to: OAuth2
  defdelegate verify(strategy, dsl_state), to: Verifier
end
