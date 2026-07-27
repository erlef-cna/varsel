# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defimpl AshAuthentication.Strategy, for: Varsel.Accounts.Strategy.Mock do
  @moduledoc """
  One phase, where a real OAuth provider has two. The request phase exists to
  send the browser to somebody else's server; there is nobody to ask here, so
  the sign-in page links straight to `callback` with a role already chosen.
  """

  alias Varsel.Accounts.Strategy.Mock

  def name(strategy), do: strategy.name

  def phases(_strategy), do: [:callback]

  def actions(_strategy), do: [:register]

  def method_for_phase(_strategy, :callback), do: :get

  def routes(strategy) do
    subject_name = AshAuthentication.Info.authentication_subject_name!(strategy.resource)

    [
      {"/#{subject_name}/#{strategy.name}/callback", :callback}
    ]
  end

  def plug(strategy, phase, conn), do: Mock.Plug.handle(conn, strategy, phase)

  def action(strategy, :register, params, options), do: Mock.Actions.register(strategy, params, options)

  def tokens_required?(_strategy), do: false
end
