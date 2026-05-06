# SPDX-FileCopyrightText: 2026 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

ExUnit.start(capture_log: true)
Ecto.Adapters.SQL.Sandbox.mode(CveManagement.Repo, :manual)
