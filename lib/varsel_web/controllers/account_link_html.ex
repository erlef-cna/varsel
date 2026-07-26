# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.AccountLinkHTML do
  @moduledoc """
  The confirmation step of linking a provider to an existing account.
  """
  use VarselWeb, :html

  embed_templates "account_link_html/*"
end
