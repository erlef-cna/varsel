# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CWE.CweXmlParser do
  @moduledoc """
  Parses the MITRE CWE XML catalog (cwec_latest.xml) as a SAX stream via
  `Varsel.Xml`, one weakness subtree at a time.

  Produces weakness maps ready for bulk-upsert into `Weakness`.

  Usage:

      xml_binary |> Varsel.Xml.chunk_binary() |> CweXmlParser.stream()

  Each map has the keys:

      %{
        cwe_id:                integer,
        name:                  string,
        abstraction:           string,
        status:                string,
        description:           string,
        extended_description:  string | nil,
        related_weaknesses:    [%{nature: atom, cwe_id: integer, view_id: integer, ordinal: string | nil}],
        potential_mitigations: string | nil,
        common_consequences:   string | nil
      }
  """

  import Varsel.Xml

  @doc """
  Lazily parses a stream of XML binary chunks into a stream of weakness maps.

  The XML must be the content of `cwec_latest.xml` from the MITRE CWE ZIP.
  Raises `Saxy.ParseError` when the stream is run over malformed input.
  """
  @spec stream(Enumerable.t(binary())) :: Enumerable.t(map())
  def stream(chunks) do
    chunks
    |> stream_subtrees("Weaknesses", "Weakness")
    |> Stream.map(&parse_weakness/1)
  end

  # ---------------------------------------------------------------------------
  # Private helpers
  # ---------------------------------------------------------------------------

  defp parse_weakness(el) do
    attrs = attributes(el)
    children = child_elements(el)

    description =
      children
      |> find_child("Description")
      |> text_content()

    extended_description =
      children
      |> find_child("Extended_Description")
      |> text_content()
      |> nil_if_blank()

    related_weaknesses =
      children
      |> find_child("Related_Weaknesses")
      |> case do
        nil -> []
        rel_el -> rel_el |> child_elements() |> Enum.map(&parse_related_weakness/1)
      end

    potential_mitigations =
      children
      |> find_child("Potential_Mitigations")
      |> case do
        nil -> nil
        mit_el -> parse_mitigations(mit_el)
      end

    common_consequences =
      children
      |> find_child("Common_Consequences")
      |> case do
        nil -> nil
        cons_el -> parse_consequences(cons_el)
      end

    %{
      cwe_id: String.to_integer(attrs["ID"]),
      name: attrs["Name"],
      abstraction: parse_abstraction(attrs["Abstraction"]),
      status: parse_status(attrs["Status"]),
      description: description,
      extended_description: extended_description,
      related_weaknesses: related_weaknesses,
      potential_mitigations: potential_mitigations,
      common_consequences: common_consequences
    }
  end

  defp parse_related_weakness(el) do
    attrs = attributes(el)

    %{
      nature: parse_nature(attrs["Nature"]),
      target_cwe_id: String.to_integer(attrs["CWE_ID"]),
      view_id: String.to_integer(attrs["View_ID"]),
      ordinal: attrs["Ordinal"]
    }
  end

  defp parse_mitigations(el) do
    el
    |> child_elements()
    |> Enum.map(fn mitigation ->
      children = child_elements(mitigation)
      phase = children |> find_child("Phase") |> text_content() |> nil_if_blank()
      desc = children |> find_child("Description") |> text_content() |> nil_if_blank()

      case {phase, desc} do
        {nil, nil} -> nil
        {nil, d} -> d
        {p, nil} -> p
        {p, d} -> "[#{p}] #{d}"
      end
    end)
    |> Enum.reject(&is_nil/1)
    |> Enum.join("\n")
    |> nil_if_blank()
  end

  defp parse_consequences(el) do
    el
    |> child_elements()
    |> Enum.map(fn consequence ->
      children = child_elements(consequence)
      scope = children |> find_child("Scope") |> text_content() |> nil_if_blank()
      impact = children |> find_child("Impact") |> text_content() |> nil_if_blank()

      case {scope, impact} do
        {nil, nil} -> nil
        {nil, i} -> i
        {s, nil} -> s
        {s, i} -> "[#{s}] #{i}"
      end
    end)
    |> Enum.reject(&is_nil/1)
    |> Enum.join("\n")
    |> nil_if_blank()
  end

  defp parse_abstraction("Pillar"), do: :pillar
  defp parse_abstraction("Class"), do: :class
  defp parse_abstraction("Base"), do: :base
  defp parse_abstraction("Variant"), do: :variant
  defp parse_abstraction("Compound"), do: :compound

  defp parse_status("Stable"), do: :stable
  defp parse_status("Draft"), do: :draft
  defp parse_status("Incomplete"), do: :incomplete
  defp parse_status("Deprecated"), do: :deprecated
  defp parse_status("Obsolete"), do: :obsolete

  # Map XML "Nature" attribute strings to our enum atoms
  defp parse_nature("ChildOf"), do: :child_of
  defp parse_nature("ParentOf"), do: :parent_of
  defp parse_nature("PeerOf"), do: :peer_of
  defp parse_nature("CanPrecede"), do: :can_precede
  defp parse_nature("CanFollow"), do: :can_follow
  defp parse_nature("RequiredBy"), do: :required_by
  defp parse_nature("Requires"), do: :requires
  defp parse_nature("CanAlsoBe"), do: :can_also_be
  defp parse_nature("StartsWith"), do: :starts_with
  # Fallback: keep as atom via String.to_atom is unsafe for arbitrary input,
  # so we use :peer_of as a safe default for unknown natures
  defp parse_nature(_other), do: :peer_of

  defp nil_if_blank(""), do: nil
  defp nil_if_blank(s), do: s
end
