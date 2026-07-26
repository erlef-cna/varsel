# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.AuthOverrides do
  @moduledoc false
  use AshAuthentication.Phoenix.Overrides

  alias AshAuthentication.Phoenix.Components

  # No banner/logo on the auth pages.
  override Components.SignIn do
    set :show_banner, false
    # Providers whose credentials are unset are hidden rather than offered as
    # links that would fail on the callback.
    set :filter_strategy, &Varsel.Secrets.strategy_enabled?/1
  end

  override Components.Confirm do
    set :show_banner, false
  end

  override Components.Reset do
    set :show_banner, false
  end
end
