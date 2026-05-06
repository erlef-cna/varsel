# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagement.Content.Page do
  @moduledoc false

  @enforce_keys [:id, :title, :body]
  defstruct [:id, :title, :body, :description]

  def build(filename, attrs, body) do
    id = filename |> Path.basename() |> Path.rootname()
    struct!(__MODULE__, [id: id, body: body] ++ Map.to_list(attrs))
  end
end
