# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.LivePagination do
  @moduledoc """
  Page navigation for `AshPhoenix.LiveView.keep_live` offset pages, driven by
  the `<.pagination>` component's "prev"/"next"/"first"/"last" targets.

  Stands in for `AshPhoenix.LiveView.change_page/3`, which crashes on pages
  read through code interfaces: those carry their page opts inside the query,
  leaving the rerun opts' `:page` nil (upstream-fixable). Besides assigning
  the new page this also syncs keep_live's stored page opts, so
  notification-driven refetches stay on the page the user is looking at.
  """

  import Phoenix.Component, only: [assign: 3]

  alias Phoenix.LiveView.Socket

  @doc "Turns the paginated assign to the target page."
  @spec change_page(Socket.t(), atom(), String.t()) ::
          Socket.t()
  def change_page(socket, assign_name, target) when target in ["prev", "next", "first", "last"] do
    page = Ash.page!(Map.fetch!(socket.assigns, assign_name), String.to_existing_atom(target))

    live_config =
      Map.update!(socket.assigns.ash_live_config, assign_name, fn config ->
        page_opts = [count: true, limit: page.limit, offset: page.offset]
        Map.update!(config, :opts, &Keyword.put(&1, :page, page_opts))
      end)

    socket
    |> assign(assign_name, page)
    |> assign(:ash_live_config, live_config)
  end
end
