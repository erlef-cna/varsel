# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Notifications.Event.Validations.ExactlyOneSubject do
  @moduledoc """
  Validates that an event is about exactly one subject: a case or a
  vulnerability report, never both and never neither.
  """

  use Ash.Resource.Validation

  @impl Ash.Resource.Validation
  def validate(changeset, _opts, _context) do
    case_id = Ash.Changeset.get_attribute(changeset, :case_id)
    report_id = Ash.Changeset.get_attribute(changeset, :vulnerability_report_id)

    if is_nil(case_id) == is_nil(report_id) do
      {:error, field: :case_id, message: "an event must be about exactly one of a case or a vulnerability report"}
    else
      :ok
    end
  end
end
