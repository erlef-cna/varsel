# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.ViewHelpers do
  @moduledoc """
  The small formatting and predicate helpers every view reaches for.

  Imported into views through `VarselWeb.html_helpers/0`, so a view uses them
  without declaring anything.
  """

  @doc """
  Whether a user is a point of contact — the role the console's own actions
  are gated on. Anonymous visitors and any other role are not.
  """
  @spec poc?(map() | nil) :: boolean()
  def poc?(%{role: :poc}), do: true
  def poc?(_user), do: false

  @doc """
  Flattens an Ash error into one message per line, for a flash.
  """
  @spec errors_to_string(term()) :: String.t()
  def errors_to_string(error) do
    error
    |> Ash.Error.to_error_class()
    |> Map.get(:errors, [])
    |> Enum.map_join("\n", &Exception.message/1)
  end

  @doc """
  Formats a timestamp as a plain date, or `placeholder` when there is none.
  """
  @spec format_date(DateTime.t() | nil, String.t()) :: String.t()
  def format_date(datetime, placeholder \\ "—")
  def format_date(nil, placeholder), do: placeholder

  def format_date(%DateTime{} = datetime, _placeholder), do: Calendar.strftime(datetime, "%Y-%m-%d")

  @doc """
  Formats a timestamp as a date and the time of day, for the views where the
  hour matters — a triage queue, an audit trail.
  """
  @spec format_datetime(DateTime.t() | nil, String.t()) :: String.t()
  def format_datetime(datetime, placeholder \\ "—")
  def format_datetime(nil, placeholder), do: placeholder

  def format_datetime(%DateTime{} = datetime, _placeholder), do: strftime(datetime, "%Y-%m-%d %H:%M")

  defp strftime(datetime, format), do: Calendar.strftime(datetime, format)
end
