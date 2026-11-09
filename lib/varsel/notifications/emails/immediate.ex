# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Notifications.Emails.ImmediateTemplate do
  @moduledoc "The HTML part of a one-event notification email."
  use MjmlEEx,
    mjml_template: "immediate.mjml.eex",
    layout: Varsel.Notifications.Emails.Layout
end
