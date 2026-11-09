# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Notifications.Emails.InviteTemplate do
  @moduledoc "The HTML part of a case invite email."
  use MjmlEEx,
    mjml_template: "invite.mjml.eex",
    layout: Varsel.Notifications.Emails.Layout
end
