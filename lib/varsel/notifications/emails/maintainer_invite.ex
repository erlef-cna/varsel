# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Notifications.Emails.MaintainerInviteTemplate do
  @moduledoc "The HTML part of the invite email for a maintainer of an affected package."
  use MjmlEEx,
    mjml_template: "maintainer_invite.mjml.eex",
    layout: Varsel.Notifications.Emails.Layout
end
