# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagement.Vault do
  @moduledoc false
  use Cloak.Vault, otp_app: :cve_management
end
