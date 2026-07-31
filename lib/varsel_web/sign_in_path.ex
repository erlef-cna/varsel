# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.SignInPath do
  @moduledoc """
  Builds the link to the sign-in page, carrying where the caller should land
  once they are signed in.

  Every way in agrees on one URL shape — the plug that reads it back is
  `VarselWeb.Plugs.ReturnPath`, and the four callers are the `require_login`
  plug, the nav's sign-in button, the 401 page, and any LiveView that turns an
  anonymous visitor away (a LiveView cannot write the session itself, so it
  hands the path over the query string like everyone else).

  Pages that ARE the way in — sign-in, register, reset, the OAuth callbacks —
  never become a return path. Returning to them after signing in would either
  bounce the caller straight back out or, worse, loop.
  """
  use VarselWeb, :verified_routes

  alias VarselWeb.Plugs.ReturnPath

  @doc """
  The sign-in path, returning afterwards to a `Plug.Conn`'s current location
  or to an explicit path.

  `nil` or a path that is itself part of signing in yields the bare sign-in
  path, so a return path never points back at the way in.
  """
  @spec for(Plug.Conn.t() | String.t() | nil) :: String.t()
  def for(conn_or_path)

  def for(%Plug.Conn{} = conn) do
    conn
    |> current_path()
    |> __MODULE__.for()
  end

  def for(path) when is_binary(path) do
    if returnable?(path) do
      ~p"/sign-in?#{[return_to: path]}"
    else
      ~p"/sign-in"
    end
  end

  def for(nil), do: ~p"/sign-in"

  @doc "Whether a path is somewhere worth coming back to after signing in."
  @spec returnable?(String.t()) :: boolean()
  def returnable?(path) when is_binary(path) do
    with {:ok, path} <- ReturnPath.safe_path(path),
         {:ok, %URI{path: path}} <- URI.new(path) do
      not auth_page?(Path.split(path))
    else
      _unsafe_or_unparseable -> false
    end
  end

  # Matching on segments rather than on the string is what makes "/resettled"
  # not count as being under "/reset". Each clause is the shape of a real
  # route: only the OAuth callbacks under "/auth" nest freely, and
  # "/password-reset/:token" is exactly two segments. `Path.split/1` keeps the
  # leading "/" as its own element.
  defp auth_page?(["/", "auth" | _rest]), do: true
  defp auth_page?(["/", "password-reset", _token]), do: true
  defp auth_page?(["/", "sign-in"]), do: true
  defp auth_page?(["/", "sign-out"]), do: true
  defp auth_page?(["/", "register"]), do: true
  defp auth_page?(["/", "reset"]), do: true
  defp auth_page?(_segments), do: false

  # The path as the caller sees it, query string included — `/cases?filter=open`
  # returns to that filter, not to the bare list.
  defp current_path(%Plug.Conn{request_path: request_path, query_string: ""}), do: request_path

  defp current_path(%Plug.Conn{request_path: request_path, query_string: query}), do: request_path <> "?" <> query
end
