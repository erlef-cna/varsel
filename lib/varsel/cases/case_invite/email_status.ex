# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.CaseInvite.EmailStatus do
  @moduledoc """
  What became of the email an invite sends to the person it names.
  """

  use Ash.Type.Enum,
    values: [
      pending: "The invite email is queued for the stored address.",
      sent: "The invite email went out to the stored address.",
      skipped: "The provider lists no address, and the inviter chose to send no email.",
      duplicate: "Another invite on the same case already emails this address."
    ]

  @doc "The short label the case page shows for a status."
  @spec label(t()) :: String.t()
  def label(:pending), do: "email queued"
  def label(:sent), do: "emailed"
  def label(:skipped), do: "no email, skipped"
  def label(:duplicate), do: "address already emailed"
end
