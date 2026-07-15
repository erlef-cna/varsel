# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.AI do
  @moduledoc """
  AI-assistant plumbing: the domain holding the internal research tools, the
  per-task model registry, and a ReqLLM-compatible transport facade that
  prompt-backed actions receive as their `req_llm` option so tests can swap
  the LLM out:

      config :varsel, :ai,
        backend: ReqLLM,
        models: [research: "anthropic:claude-sonnet-5"]

  The Anthropic API key is read by ReqLLM from the `ANTHROPIC_API_KEY`
  environment variable.
  """

  use Ash.Domain, otp_app: :varsel, extensions: [AshAi]

  alias Varsel.AI.Tools

  # ⚠️ Internal only: these exist for the prompt-backed actions' tool loop.
  # Never add them to the MCP router's tool list or GraphQL — a server-side
  # URL fetcher callable by API users is an open proxy / SSRF primitive.
  tools do
    tool :fetch_url, Tools, :fetch_url
    tool :hex_package_info, Tools, :hex_package_info
  end

  resources do
    resource Tools
  end

  @doc "The configured ReqLLM model spec for a task."
  @spec model!(atom()) :: String.t()
  def model!(task) do
    :varsel
    |> Application.fetch_env!(:ai)
    |> Keyword.fetch!(:models)
    |> Keyword.fetch!(task)
  end

  @doc false
  @spec backend() :: module()
  def backend do
    :varsel |> Application.fetch_env!(:ai) |> Keyword.fetch!(:backend)
  end

  # ReqLLM-compatible surface, delegated to the configured backend. The tool
  # loop streams; the structured final answer uses generate_object.

  @doc false
  def generate_text(model, messages, opts \\ []), do: backend().generate_text(model, messages, opts)

  @doc false
  def stream_text(model, messages, opts \\ []), do: backend().stream_text(model, messages, opts)

  @doc false
  def generate_object(model, messages, schema, opts \\ []) do
    backend().generate_object(model, messages, schema, opts)
  end
end
