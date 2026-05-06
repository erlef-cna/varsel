# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagement.Content do
  @moduledoc false

  use NimblePublisher,
    build: CveManagement.Content.Page,
    from: Application.app_dir(:cve_management, "priv/pages/*.md"),
    as: :pages

  @pages_by_id Map.new(@pages, &{&1.id, &1})

  def get_page!(id), do: Map.fetch!(@pages_by_id, id)
end
