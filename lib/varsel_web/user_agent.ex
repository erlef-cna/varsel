# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.UserAgent do
  @moduledoc """
  Names the browser and platform a user agent string claims to be.

  Enough for someone to recognise their own machine in a list of sessions.
  The string is self-reported, so it identifies nothing on its own.
  """

  # Most specific first: Edge and Opera also say "Chrome", Chrome says "Safari".
  @browsers [
    {"Edg/", "Edge"},
    {"OPR/", "Opera"},
    {"Chrome/", "Chrome"},
    {"Firefox/", "Firefox"},
    {"Safari/", "Safari"}
  ]

  @platforms [
    {"Windows", "Windows"},
    {"Macintosh", "macOS"},
    {"iPhone", "iPhone"},
    {"iPad", "iPad"},
    {"Android", "Android"},
    {"Linux", "Linux"}
  ]

  @doc """
  A short label like `"Chrome on macOS"`, or the string itself if it matches
  nothing known.
  """
  @spec describe(String.t() | nil) :: String.t() | nil
  def describe(nil), do: nil

  def describe(user_agent) do
    case {match(@browsers, user_agent), match(@platforms, user_agent)} do
      {nil, nil} -> user_agent
      {browser, nil} -> browser
      {nil, platform} -> platform
      {browser, platform} -> "#{browser} on #{platform}"
    end
  end

  defp match(candidates, user_agent) do
    Enum.find_value(candidates, fn {token, name} ->
      String.contains?(user_agent, token) && name
    end)
  end
end
