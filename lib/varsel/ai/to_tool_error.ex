# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

# Generic actions returning `{:error, "message"}` surface as UnknownError;
# without this impl ash_ai hands the model a generic "something went wrong"
# and it retries blindly instead of adapting to the actual reason.
defimpl AshAi.ToToolError, for: Ash.Error.Unknown.UnknownError do
  def to_tool_error(%{error: message}) when is_binary(message), do: message
  def to_tool_error(%{error: error}) when is_exception(error), do: Exception.message(error)
  def to_tool_error(error), do: Exception.message(error)
end
