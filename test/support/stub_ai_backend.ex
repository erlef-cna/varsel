# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Test.StubAIBackend do
  @moduledoc """
  Scripted LLM double for prompt-backed actions (`config :varsel, :ai`).

  Tests declare the assistant's turns up front; each `stream_text` call pops
  the next step, each `generate_object` call (the structured final answer)
  pops a `{:result, value}` step:

      StubAIBackend.stub_script([
        {:tool_calls, [{"create_case_proposal", %{"case_id" => id, ...}}]},
        {:text, "Filed one proposal."},
        {:result, "Filed one proposal."}
      ])

  The received contexts are recorded and can be inspected via `requests/0`.
  """

  @script_key {__MODULE__, :script}
  @requests_key {__MODULE__, :requests}

  @type step ::
          {:tool_calls, [{String.t(), map()}]}
          | {:text, String.t()}
          | {:result, term()}

  @spec stub_script([step()]) :: :ok
  def stub_script(steps) do
    :persistent_term.put(@script_key, steps)
    :persistent_term.put(@requests_key, [])

    ExUnit.Callbacks.on_exit(fn ->
      :persistent_term.erase(@script_key)
      :persistent_term.erase(@requests_key)
    end)

    :ok
  end

  @doc "The `{function, messages}` calls received so far, in order."
  @spec requests() :: [{atom(), [ReqLLM.Message.t()]}]
  def requests, do: @requests_key |> :persistent_term.get([]) |> Enum.reverse()

  # ReqLLM-compatible surface -------------------------------------------------

  def generate_text(_model, _messages, _opts) do
    raise "StubAIBackend received generate_text/3 — prompt actions stream"
  end

  def stream_text(model, messages, _opts) do
    record(:stream_text, messages)

    chunks =
      case pop!() do
        {:tool_calls, calls} ->
          # Ids must be unique across the whole run: the tool loop skips
          # calls whose id already has a result in the transcript.
          for {name, arguments} <- calls do
            id = "call_#{:erlang.unique_integer([:positive])}"
            ReqLLM.StreamChunk.tool_call(name, arguments, %{id: id})
          end

        {:text, text} ->
          [ReqLLM.StreamChunk.text(text)]

        other ->
          raise "StubAIBackend: expected a :tool_calls or :text step, got #{inspect(other)}"
      end

    {:ok,
     %ReqLLM.StreamResponse{
       stream: chunks,
       metadata_handle: nil,
       cancel: {__MODULE__, :noop, []},
       model: model,
       context: ReqLLM.Context.new(messages)
     }}
  end

  def generate_object(_model, messages, _schema, _opts) do
    record(:generate_object, messages)

    case pop!() do
      {:result, value} -> {:ok, %{object: %{"result" => value}}}
      other -> raise "StubAIBackend: expected a :result step, got #{inspect(other)}"
    end
  end

  @doc false
  def noop, do: :ok

  defp pop! do
    case :persistent_term.get(@script_key, []) do
      [] ->
        raise "StubAIBackend: script exhausted — declare more steps via stub_script/1"

      [step | rest] ->
        :persistent_term.put(@script_key, rest)
        step
    end
  end

  defp record(function, messages) do
    requests = :persistent_term.get(@requests_key, [])
    :persistent_term.put(@requests_key, [{function, messages} | requests])
  end
end
