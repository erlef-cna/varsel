# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagement.ReportChannels.GitHubAdvisory.IdentifierType do
  @moduledoc false
  use Ash.Type.Enum, values: [:cve, :ghsa]
end
