# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.GitHub.Errors.RequestFailed do
  @moduledoc """
  GitHub did not answer a request of the GitHub App's token layer as
  expected, or the request did not reach GitHub.
  """

  use Splode.Error, fields: [:reason], class: :unknown

  @impl Exception
  def message(%{reason: reason}), do: "The GitHub request failed: #{inspect(reason)}"
end
