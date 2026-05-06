# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagement.ReportChannels.GitHubAdvisory.State do
  @moduledoc false
  use Ash.Type.Enum, values: [:published, :closed, :withdrawn, :draft, :triage]
end
