# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.UnauthorizedError do
  @moduledoc """
  Nobody is signed in, and the request needs someone to be. Answers 401.
  """

  defexception message: "You must be signed in to view this page.", plug_status: 401
end
