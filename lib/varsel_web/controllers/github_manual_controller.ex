# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.GitHubManualController do
  @moduledoc """
  The two steps of the command that a `Varsel.Cases.GitHubManualRequest`
  gives a POC: the request to send to GitHub, and GitHub's answer to record.
  Both carry the request's one-time token as a bearer token. The answers are
  short JSON for a terminal.
  """

  use VarselWeb, :controller

  alias Ash.Error.Changes.StaleRecord
  alias Ash.Error.Forbidden
  alias Ash.Error.Invalid
  alias Varsel.Cases
  alias Varsel.Service
  alias VarselWeb.AdvisoryComponents

  @doc "Answers the body to send to GitHub, `{}` for a read."
  def request(conn, %{"id" => id}) do
    with {:ok, token} <- bearer(conn),
         {:ok, request} <- locate(id),
         {:ok, request} <-
           step(Cases.fetch_github_manual_request(request, token, actor: service())) do
      json(conn, request.body || %{})
    else
      {:error, status, message} -> refuse(conn, status, message)
    end
  end

  @doc "Records GitHub's answer, the request body."
  def result(conn, %{"id" => id}) do
    answer = conn.body_params

    with :ok <- json_body(conn),
         {:ok, token} <- bearer(conn),
         {:ok, request} <- locate(id),
         {:ok, request} <-
           step(Cases.complete_github_manual_request(request, token, answer, actor: service())) do
      json(conn, %{ok: true, message: recorded(request, answer)})
    else
      {:error, status, message} -> refuse(conn, status, message)
    end
  end

  defp service, do: Service.github_manual()

  defp json_body(conn) do
    case get_req_header(conn, "content-type") do
      ["application/json" <> _params] ->
        :ok

      _other ->
        {:error, :unsupported_media_type, "Send GitHub's answer as JSON (Content-Type: application/json)."}
    end
  end

  defp bearer(conn) do
    case get_req_header(conn, "authorization") do
      ["Bearer " <> token] -> {:ok, String.trim(token)}
      _other -> {:error, :unauthorized, "The request's token is missing."}
    end
  end

  defp locate(id) do
    case Cases.locate_github_manual_request(id, actor: service()) do
      {:ok, request} ->
        {:ok, request}

      {:error, _not_found} ->
        {:error, :not_found, "There is no such request. It may have been cleaned up."}
    end
  end

  defp step({:ok, request}), do: {:ok, request}

  defp step({:error, %Forbidden{}}),
    do: {:error, :unauthorized, "The token is not this request's, or the request has expired. Prepare a new one."}

  defp step({:error, %Invalid{errors: errors} = error}) do
    cond do
      Enum.any?(errors, &match?(%StaleRecord{}, &1)) ->
        {:error, :conflict, "This request is done already. Prepare a new one."}

      answer = Enum.find(errors, &match?(%{field: :answer}, &1)) ->
        {:error, :unprocessable_entity, "GitHub's answer #{answer.message}."}

      true ->
        raise error
    end
  end

  defp step({:error, error}), do: raise(Ash.Error.to_error_class(error))

  defp refuse(conn, status, message) do
    conn
    |> maybe_challenge(status)
    |> put_status(status)
    |> json(%{ok: false, message: message})
  end

  defp maybe_challenge(conn, :unauthorized),
    do: put_resp_header(conn, "www-authenticate", ~s(Bearer error="invalid_token"))

  defp maybe_challenge(conn, _status), do: conn

  defp recorded(%{operation: :read, advisory_url: url, ghsa_id: ghsa_id}, _answer) when is_binary(url),
    do: "Linked #{ghsa_id} to the case."

  defp recorded(%{operation: :read, fields: [_field | _rest] = fields, ghsa_id: ghsa_id}, _answer),
    do: "Read #{ghsa_id} again and pulled #{Enum.map_join(fields, ", ", &AdvisoryComponents.field_label/1)}."

  defp recorded(%{operation: :read, ghsa_id: ghsa_id}, _answer), do: "Read #{ghsa_id} again."

  defp recorded(%{operation: :push, ghsa_id: ghsa_id}, _answer),
    do: "Pushed to #{ghsa_id}. The case now holds the advisory as GitHub answered."

  defp recorded(%{operation: :report, path: path}, answer) do
    if String.ends_with?(path, "/reports"),
      do: "Reported to the maintainers. #{answer["ghsa_id"]} is linked to the case.",
      else: "Opened the draft advisory #{answer["ghsa_id"]}. It is linked to the case."
  end
end
