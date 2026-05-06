# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagement.ReportChannels.GitHubAdvisory.CreditType do
  @moduledoc false
  use Ash.Type.Enum,
    values: [
      :analyst,
      :finder,
      :reporter,
      :coordinator,
      :remediation_developer,
      :remediation_reviewer,
      :remediation_verifier,
      :tool,
      :sponsor,
      :other
    ]
end
