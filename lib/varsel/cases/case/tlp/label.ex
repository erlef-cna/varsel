# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Case.Tlp.Label do
  @moduledoc """
  A Traffic Light Protocol (TLP 2.0) label: how far the people who read the
  information may share it.

  The wording follows the CISA definitions and the TLP 2.0 user guide, see
  `definitions_url/0` and `user_guide_url/0`.
  """

  @behaviour AshGraphql.Type

  use Ash.Type.Enum,
    values: [
      red: "For the eyes and ears of individual recipients only. Recipients may not share it with anyone else.",
      amber_strict: "Recipients may share it only inside their own organization, on a need-to-know basis.",
      amber: "Recipients may share it inside their organization and with its clients, on a need-to-know basis.",
      green: "Recipients may share it with peers and partners in their community, but not on public channels.",
      clear: "Recipients may share it with anyone. There is no limit on disclosure."
    ]

  @impl AshGraphql.Type
  def graphql_type(_constraints), do: :case_tlp_label

  @impl AshGraphql.Type
  def graphql_input_type(_constraints), do: :case_tlp_label

  @doc "The label as TLP 2.0 writes it, e.g. `TLP:AMBER+STRICT`."
  @spec label(t()) :: String.t()
  def label(:clear), do: "TLP:CLEAR"
  def label(:green), do: "TLP:GREEN"
  def label(:amber), do: "TLP:AMBER"
  def label(:amber_strict), do: "TLP:AMBER+STRICT"
  def label(:red), do: "TLP:RED"

  @doc "When a source uses the label, with the notes the TLP 2.0 user guide adds."
  @spec guidance(t()) :: String.t()
  def guidance(:red),
    do:
      "Use it when other parties cannot act on the information without significant risk to the privacy, " <>
        "reputation or operations of the organizations involved. In a meeting, it stays with the people present."

  def guidance(:amber_strict),
    do:
      "Use it when the information needs support to act on, but sharing it outside the recipient's " <>
        "organization puts privacy, reputation or operations at risk."

  def guidance(:amber),
    do:
      "Use it when the information needs support to act on, but sharing it outside the organizations involved " <>
        "puts privacy, reputation or operations at risk. Clients are those who get cybersecurity services " <>
        "from the organization."

  def guidance(:green),
    do:
      "Use it when the information helps to increase awareness in the wider community. " <>
        "When nobody defines the community, it is the cybersecurity community."

  def guidance(:clear),
    do: "Use it when the information carries minimal or no foreseeable risk of misuse. Standard copyright rules apply."

  @doc "The CISA page that defines the TLP 2.0 labels."
  @spec definitions_url() :: String.t()
  def definitions_url, do: "https://www.cisa.gov/news-events/news/traffic-light-protocol-tlp-definitions-and-usage"

  @doc "The CISA TLP 2.0 user guide."
  @spec user_guide_url() :: String.t()
  def user_guide_url, do: "https://www.cisa.gov/sites/default/files/2023-02/tlp-2-0-user-guide_508c.pdf"
end
