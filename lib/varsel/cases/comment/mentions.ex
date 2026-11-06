# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Comment.Mentions do
  @moduledoc """
  The mentions a comment body holds.

  A mention is a markdown link whose target is `mention:` and the mentioned
  account's id, written by the composer as `[@Name](mention:<id>)`. The name
  is what the writer saw when they picked the person; the id is what the
  notification goes to.
  """

  @uuid ~r/\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/i

  @token ~r/\[@([^\[\]]*)\]\(mention:([0-9a-fA-F-]{36})\)/

  @doc "The markdown that mentions the account `id` under `name`."
  @spec token(Ash.UUID.t(), String.t()) :: String.t()
  def token(id, name) when is_binary(id) and is_binary(name) do
    "[@#{String.replace(name, ["[", "]"], "")}](mention:#{id})"
  end

  @doc """
  The account id a mention link points at, or nil when `url` is no mention.
  """
  @spec user_id(String.t()) :: Ash.UUID.t() | nil
  def user_id("mention:" <> id) do
    if Regex.match?(@uuid, id), do: String.downcase(id)
  end

  def user_id(_url), do: nil

  @doc """
  The distinct accounts `body` mentions, in the order they first appear. A
  mention inside code is text, not a mention.
  """
  @spec user_ids(String.t()) :: [Ash.UUID.t()]
  def user_ids(body) when is_binary(body) do
    {_document, ids} =
      body
      |> MDEx.parse_document!()
      |> MDEx.traverse_and_update([], fn
        %MDEx.Link{url: url} = link, ids ->
          case user_id(url) do
            nil -> {link, ids}
            id -> {link, [id | ids]}
          end

        node, ids ->
          {node, ids}
      end)

    ids |> Enum.reverse() |> Enum.uniq()
  end

  @doc """
  `body` with every mention written as the bold name it carries. GitHub
  turns `@login` into a mention of its own account, which is a person the
  writer did not mean.
  """
  @spec to_names(String.t()) :: String.t()
  def to_names(body) when is_binary(body), do: Regex.replace(@token, body, "**\\1**")
end
