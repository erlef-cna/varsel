# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Content do
  @moduledoc false

  use NimblePublisher,
    build: Varsel.Content.Page,
    from: Application.app_dir(:varsel, "priv/pages/*.md"),
    as: :pages,
    # header_id_prefix makes Comrak emit a clickable `<a class="anchor" id="…">`
    # permalink inside every heading (Page.build reads those ids back into the
    # table of contents). block_directive enables `:::name … :::` fences that
    # render `<div class="name">…</div>` — used for `:::steps` step cards on the
    # process pages without affecting plain lists.
    comrak_options: [extension: [header_id_prefix: "", block_directive: true]]

  @pages_by_id Map.new(@pages, &{&1.id, &1})

  def get_page!(id), do: Map.fetch!(@pages_by_id, id)
end
