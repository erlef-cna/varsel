# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Phoenix.Components.Strategy.Mock do
  @moduledoc """
  The mock provider's buttons on the sign-in page: one per role.

  `AshAuthentication.Phoenix.Components.SignIn` derives a component module from
  each strategy's struct name and quietly drops any strategy whose module does
  not exist, so a strategy of ours has to bring its own.

  A real provider gets one button because the choice of *who you are* happens
  on the provider's own site. Here that choice is the role, and it is known up
  front, so the roles are offered directly and each links to the callback with
  its role already picked.
  """

  use AshAuthentication.Phoenix.Web, :live_component

  import AshAuthentication.Phoenix.Components.Helpers, only: [auth_path: 6]
  import VarselWeb.CoreComponents, only: [icon: 1]

  alias AshAuthentication.Info
  alias Varsel.Accounts.Strategy.Mock

  @doc false
  @impl Phoenix.LiveComponent
  def render(assigns) do
    assigns =
      assigns
      |> assign(:roles, Mock.roles())
      |> assign(:subject_name, Info.authentication_subject_name!(assigns.strategy.resource))
      |> assign_new(:auth_routes_prefix, fn -> nil end)

    ~H"""
    <div class="w-full space-y-2">
      <.link
        :for={{uid, label, _role} <- @roles}
        href={
          auth_path(@socket, @subject_name, @auth_routes_prefix, @strategy, :callback, %{
            "role" => uid
          })
        }
        class="btn btn-block btn-outline btn-warning"
      >
        <.icon name="hero-code-bracket" class="size-4" /> Sign in as {label}
      </.link>
    </div>
    """
  end
end
