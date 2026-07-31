# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Plugs.ReturnPath do
  @moduledoc """
  Carries "send me back here once I am signed in" from the sign-in link's
  query string into the session.

  A query parameter cannot survive the trip on its own: signing in leaves
  this domain for the OAuth provider and comes back to a callback that never
  saw the original link. The session can span that, so this plug promotes
  `?return_to=` into it on the way in, and `VarselWeb.AuthController.success/4`
  spends it on the way out.

  Only ever set on the way IN. `:auth_browser` also carries `/sign-out`,
  which reads the same session key, so a plug that fired everywhere on that
  pipeline would let `/sign-out?return_to=…` choose where signing out lands —
  the request would be answered by dropping the caller back on a page they
  just left, rather than on the home page. `sign_in_request?/1` keeps this to
  the pages that are actually a way in.

  ## Where a caller may be sent

  The stored value is a path on this site, never a URL: see `safe_path/1`.
  Anything it rejects is dropped rather than corrected — a refused return
  path costs the caller one extra click, while an honoured one that leaves
  the site turns the sign-in link into an open redirect.
  """
  @behaviour Plug

  import Plug.Conn, only: [put_session: 3]

  @session_key :return_to

  @doc "The session key naming where to go once signed in."
  @spec session_key() :: atom()
  def session_key, do: @session_key

  @impl Plug
  def init(opts), do: opts

  @impl Plug
  def call(%{params: %{"return_to" => return_to}} = conn, _opts) when is_binary(return_to) do
    with true <- sign_in_request?(conn),
         {:ok, path} <- safe_path(return_to) do
      put_session(conn, @session_key, path)
    else
      _not_a_return_path -> conn
    end
  end

  def call(conn, _opts), do: conn

  # Signing out is on the same pipeline and spends the same key, so only the
  # ways IN may set it.
  defp sign_in_request?(%Plug.Conn{path_info: ["auth" | _rest]}), do: true
  defp sign_in_request?(%Plug.Conn{path_info: ["sign-in"]}), do: true
  defp sign_in_request?(%Plug.Conn{path_info: ["register"]}), do: true
  defp sign_in_request?(%Plug.Conn{path_info: ["reset"]}), do: true
  defp sign_in_request?(%Plug.Conn{}), do: false

  @doc """
  A same-site path safe to hand a browser, or `:error`.

  Two checks have to agree, because neither is sufficient alone: Elixir's
  `URI` implements RFC 3986, while the browser doing the navigating
  implements the WHATWG URL spec, and the two disagree about what counts as
  a host.

  A query string and fragment are kept; they belong to the page being
  returned to (`/cases?filter=open`).
  """
  @spec safe_path(String.t()) :: {:ok, String.t()} | :error
  def safe_path(return_to) do
    with {:ok, path} <- absolute_path(return_to) do
      whatwg_safe_path(path)
    end
  end

  # Refuses anything carrying a scheme or an authority — `https://evil.com`,
  # `javascript:alert(1)`, `//evil.com` (protocol-relative, which a browser
  # resolves to that host rather than to a path here).
  #
  # Asserts the input is ALREADY the canonical spelling of itself rather than
  # normalising it: stripping the origin and rebuilding has to give back the
  # exact string that came in. A URL carrying an origin loses it and stops
  # matching, and anything `URI.new/1` will not parse (a backslash, a raw
  # newline, a space) never gets this far. Refusing beats rewriting, since a
  # value that means one thing to `URI` and another to the browser is exactly
  # the bug being guarded against.
  @spec absolute_path(String.t()) :: {:ok, String.t()} | :error
  defp absolute_path(return_to) do
    with {:ok, %URI{} = uri} <- URI.new(return_to),
         ^return_to <- URI.to_string(%{uri | scheme: nil, host: nil, port: nil}) do
      {:ok, return_to}
    else
      _not_canonical_or_error -> :error
    end
  end

  # The spellings that parse and round-trip cleanly, so `absolute_path/1`
  # waves them through, but still do not name a page here:
  #
  #   * `/%2fevil.com` and `/%5cevil.com` — proxies and servers have
  #     historically decoded these back into `//` and `/\` before the browser
  #     sees them, and WHATWG folds `\` into `/`.
  #   * `evil.com` — no leading slash, so a browser resolves it against the
  #     current directory rather than the site root.
  #
  # Accepts `/` itself, or a leading `/` followed by a character that cannot
  # begin an authority. Checking against an allowed set, rather than
  # blocklisting `//` and `/\`, is what keeps the next spelling out too.
  @spec whatwg_safe_path(String.t()) :: {:ok, String.t()} | :error
  defp whatwg_safe_path("/"), do: {:ok, "/"}

  defp whatwg_safe_path("/" <> rest = path) do
    if host_like?(rest), do: :error, else: {:ok, path}
  end

  defp whatwg_safe_path(_return_to), do: :error

  defp host_like?(<<first::utf8, _rest::binary>>) do
    first not in ~c"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_~."
  end

  defp host_like?(_rest), do: true
end
