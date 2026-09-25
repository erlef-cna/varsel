# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

# Renders `AshRateLimiter.LimitExceeded` on the GraphQL, MCP and form surfaces.
# Without these impls GraphQL and MCP mask the error as a generic "something
# went wrong" / "unexpected error occurred", and AshPhoenix drops it from the
# form with a warning.

defimpl AshGraphql.Error, for: AshRateLimiter.LimitExceeded do
  def to_error(error) do
    %{
      message: Exception.message(error),
      short_message: Exception.message(error),
      vars: %{},
      code: "rate_limited",
      fields: []
    }
  end
end

defimpl AshAi.ToToolError, for: AshRateLimiter.LimitExceeded do
  def to_tool_error(error) do
    Exception.message(error)
  end
end

# The limit applies to the whole submission and not to one input, so the error
# goes on `:base`. A form renders it with `translate_errors(@form.errors, :base)`.
defimpl AshPhoenix.FormData.Error, for: AshRateLimiter.LimitExceeded do
  def to_form_error(error) do
    {:base, "Limit of %{limit} per %{period} reached. Try again later.", limit: error.limit, period: period(error.per)}
  end

  defp period(milliseconds) do
    seconds = div(milliseconds, 1000)

    [
      day: div(seconds, 86_400),
      hour: seconds |> div(3600) |> rem(24),
      minute: seconds |> div(60) |> rem(60),
      second: rem(seconds, 60)
    ]
    |> Duration.new!()
    |> Duration.to_string()
  end
end
