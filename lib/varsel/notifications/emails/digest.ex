# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Notifications.Emails.DigestTemplate do
  @moduledoc "The HTML part of the daily notification digest."
  use MjmlEEx,
    mjml_template: "digest.mjml.eex",
    layout: Varsel.Notifications.Emails.Layout
end
