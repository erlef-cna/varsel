# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.LiveCurrentPath do
  @moduledoc """
  Assigns `:current_path`, the path a LiveView is currently showing, for
  `VarselWeb.Layouts.app/1` to resolve the active nav section from.

  It hooks `handle_params` rather than reading the URI at mount because a live
  redirect between two routes of the same live session does not re-mount:
  mounting alone would leave every later page highlighting the section the
  session started in.
  """

  import Phoenix.Component, only: [assign: 3]
  import Phoenix.LiveView, only: [attach_hook: 4]

  def on_mount(:default, _params, _session, socket) do
    {:cont,
     attach_hook(socket, __MODULE__, :handle_params, fn _params, uri, socket ->
       {:cont, assign(socket, :current_path, URI.parse(uri).path)}
     end)}
  end
end
