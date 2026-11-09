# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Notifications.Emails.Layout do
  @moduledoc "The branded MJML frame every HTML email renders inside."
  use MjmlEEx.Layout, mjml_layout: "layout.mjml.eex"
end
