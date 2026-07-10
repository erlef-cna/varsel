# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

[
  # Upstream: ash_authentication_phoenix references Ash.Resource.record/0 which
  # is not exported. Fixed upstream but not yet released — remove this line once
  # https://github.com/team-alembic/ash_authentication_phoenix/commit/9edd90969adbe91df7a3ee652004d08a463f555e
  # is released.
  {"lib/ash_authentication_phoenix/controller.ex", :unknown_type}
]
