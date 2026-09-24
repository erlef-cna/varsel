# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CVE.CveValidation.Actions.Validate do
  @moduledoc """
  Runs one CVE record validator and wraps its findings in a
  `Varsel.CVE.CveValidation.Result`.

  The `:validator` option names which validator to run, so all five
  validation actions share one implementation.
  """

  use Ash.Resource.Actions.Implementation

  alias Varsel.CVE.CveValidation.Validators

  @impl Ash.Resource.Actions.Implementation
  def run(input, opts, _context) do
    cve_json = input.arguments.cve_json

    errors =
      case Keyword.fetch!(opts, :validator) do
        :all -> Validators.errors(cve_json)
        :schema -> Validators.schema_errors(cve_json)
        :cvelint -> Validators.cvelint_errors(cve_json)
        :hex -> Validators.hex_errors(cve_json)
        :eef -> Validators.eef_errors(cve_json)
      end

    {:ok, Validators.result(errors)}
  end
end
