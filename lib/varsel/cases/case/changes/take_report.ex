# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Case.Changes.TakeReport do
  @moduledoc """
  Fills the intake actions' `:report` argument with the vulnerability report
  the case opens for, and titles the case from its summary.

  A report from hex.pm also fills `:people`: the reporter and the
  maintainers hex.pm named, by handle. The report keeps the reporter's
  handle, which makes the account that later signs in with it the reporter.
  """

  use Ash.Resource.Change

  alias Ash.Changeset
  alias Varsel.Accounts

  # `Varsel.Cases.Case`'s title column; the summary may be longer.
  @title_length 500

  @impl Ash.Resource.Change
  def change(changeset, _opts, context) do
    summary = Changeset.get_argument(changeset, :summary)

    changeset
    |> Changeset.change_attribute(:title, summary && String.slice(summary, 0, @title_length))
    |> take(changeset.action.name, summary, context)
  end

  # Without an actor the action's policy refuses the submission. The
  # changeset is still built, for `can?` before anyone signed in.
  # The form shows `report_json` when the reporter switches to JSON, so the
  # wrapped body goes there too.
  defp take(changeset, :submit_report, summary, context) do
    report_json = report_json(changeset)

    changeset
    |> Changeset.set_argument(:report_json, report_json)
    |> Changeset.set_argument(:report, %{
      summary: summary,
      report_json: report_json,
      source: :web,
      reporter_id: context.actor && context.actor.id
    })
  end

  defp take(changeset, :submit_report_from_hex, summary, _context) do
    report_json = Changeset.get_argument(changeset, :report_json)
    username = Changeset.get_argument(changeset, :reporter_username)

    changeset
    |> Changeset.set_argument(:report, %{
      summary: summary,
      report_json: report_json,
      source: :hex,
      reporter_strategy: :hex,
      reporter_username: username,
      reporter_id: owner(username)
    })
    |> Changeset.set_argument(:people, [
      reporter(changeset, username) | maintainers(changeset, report_json)
    ])
  end

  # A structured `report_json` wins over a free-text body, so a structured
  # submission is never clobbered when both arrive.
  defp report_json(changeset) do
    case {Changeset.get_argument(changeset, :report_json), Changeset.get_argument(changeset, :report_body)} do
      {nil, body} when is_binary(body) -> %{"report" => body}
      {report_json, _body} -> report_json
    end
  end

  defp owner(nil), do: nil

  defp owner(username) do
    case Accounts.get_identity_for_handle("hex", username, actor: Varsel.Service.identity_claim()) do
      {:ok, %{user_id: user_id}} -> user_id
      _no_owner -> nil
    end
  end

  defp reporter(changeset, username) do
    %{
      strategy: :hex,
      username: username,
      email: Changeset.get_argument(changeset, :reporter_email),
      note: "Reported the issue on hex.pm"
    }
  end

  defp maintainers(changeset, report_json) do
    package = report_json && report_json["package"]

    for maintainer <- List.wrap(Changeset.get_argument(changeset, :maintainers)) do
      %{
        strategy: :hex,
        username: maintainer[:username] || maintainer["username"],
        email: maintainer[:email] || maintainer["email"],
        note: "Maintains #{package} on hex.pm"
      }
    end
  end
end
