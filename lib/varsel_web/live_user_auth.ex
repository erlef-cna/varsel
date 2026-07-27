# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.LiveUserAuth do
  @moduledoc """
  Helpers for authenticating users in LiveViews.
  """

  use VarselWeb, :verified_routes

  import Phoenix.Component

  alias AshAuthentication.Phoenix.LiveSession
  alias VarselWeb.Layouts

  # This is used for nested liveviews to fetch the current user.
  # To use, place the following at the top of that liveview:
  # on_mount {VarselWeb.LiveUserAuth, :current_user}
  def on_mount(:current_user, _params, session, socket) do
    {:cont, LiveSession.assign_new_resources(socket, session)}
  end

  # A live reconnect resolves the user for the LiveView process instead of
  # inheriting the conn's, and `ash_authentication_live_session` takes no load
  # option, so the nav's fields are filled in here. Calculations record no
  # loaded-ness on the struct, so `lazy?` cannot tell the reconnect from the
  # mount that already has them and both pay for the load.
  def on_mount(:live_user, _params, _session, socket) do
    case socket.assigns[:current_user] do
      nil -> {:cont, assign(socket, :current_user, nil)}
      user -> {:cont, assign(socket, :current_user, Ash.load!(user, Layouts.nav_user_load()))}
    end
  end
end
