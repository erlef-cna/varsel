# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Content.Compiler do
  @moduledoc """
  Compiles the pages a module lists with `page/1` into it.

  Each page is read and rendered at compile time, and registered as an
  `@external_resource` so editing the markdown recompiles the module.
  """

  alias Varsel.Content.Page

  defmacro __using__(_opts) do
    quote do
      import Varsel.Content.Compiler, only: [page: 1]

      Module.register_attribute(__MODULE__, :pages, accumulate: true)
      @before_compile Varsel.Content.Compiler
    end
  end

  @doc """
  Adds the page at `filename`, relative to `priv/pages`.
  """
  defmacro page(filename) do
    quote bind_quoted: [filename: filename] do
      path = Application.app_dir(:varsel, Path.join("priv/pages", filename))

      @external_resource path
      @pages Varsel.Content.Compiler.compile(path)
    end
  end

  @doc false
  # The path comes from a `page/1` call in source, read at compile time.
  # sobelow_skip ["Traversal.FileModule"]
  @spec compile(String.t()) :: Page.t()
  def compile(path), do: Page.build(path, File.read!(path))

  defmacro __before_compile__(env) do
    by_id = env.module |> Module.get_attribute(:pages) |> Map.new(&{&1.id, &1})

    quote do
      @doc "The page with `id`, raising when the module lists no such page."
      @spec get_page!(String.t()) :: Varsel.Content.Page.t()
      def get_page!(id), do: Map.fetch!(unquote(Macro.escape(by_id)), id)
    end
  end
end
