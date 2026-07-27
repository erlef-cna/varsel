# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

# Renders `AshRateLimiter.LimitExceeded` on the GraphQL and MCP surfaces.
# Without these impls both mask the error as a generic "something went
# wrong" / "unexpected error occurred".

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
