# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CWE.CweXmlParser do
  @moduledoc """
  Parses the MITRE CWE XML catalog (cwec_latest.xml) using Erlang's built-in
  `:xmerl_scan`.

  Returns a list of weakness maps ready for bulk-upsert into `Weakness`.

  Usage:

      weaknesses = CweXmlParser.parse!(xml_binary)

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

  require Record

  Record.defrecord(:xmlElement, Record.extract(:xmlElement, from_lib: "xmerl/include/xmerl.hrl"))

  Record.defrecord(
    :xmlAttribute,
    Record.extract(:xmlAttribute, from_lib: "xmerl/include/xmerl.hrl")
  )

  Record.defrecord(:xmlText, Record.extract(:xmlText, from_lib: "xmerl/include/xmerl.hrl"))

  @doc """
  Parses the given XML binary and returns a list of weakness maps.

  The XML must be the content of `cwec_latest.xml` from the MITRE CWE ZIP.
  Raises on parse failure.
  """
  @spec parse!(binary()) :: [map()]
  def parse!(xml) when is_binary(xml) do
    {root, _rest} = :xmerl_scan.string(:erlang.binary_to_list(xml), quiet: true)
    extract_weaknesses(root)
  end

  # ---------------------------------------------------------------------------
  # Private helpers
  # ---------------------------------------------------------------------------

  defp extract_weaknesses(root) do
    root
    |> child_elements()
    |> Enum.find(&(element_name(&1) == "Weaknesses"))
    |> case do
      nil -> []
      weaknesses_el -> weaknesses_el |> child_elements() |> Enum.map(&parse_weakness/1)
    end
  end

  defp parse_weakness(el) do
    attrs = attributes_map(el)
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
    attrs = attributes_map(el)

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

  # ---------------------------------------------------------------------------
  # xmerl record helpers
  # ---------------------------------------------------------------------------

  defp child_elements(nil), do: []

  defp child_elements(el) do
    el
    |> xmlElement(:content)
    |> Enum.filter(&match?(xmlElement(), &1))
  end

  defp element_name(el) do
    el |> xmlElement(:name) |> to_string()
  end

  defp find_child(children, name) do
    Enum.find(children, &(element_name(&1) == name))
  end

  defp attributes_map(el) do
    el
    |> xmlElement(:attributes)
    |> Map.new(fn attr ->
      name = attr |> xmlAttribute(:name) |> to_string()
      value = attr |> xmlAttribute(:value) |> to_string()
      {name, value}
    end)
  end

  defp text_content(nil), do: ""

  defp text_content(el) do
    el
    |> collect_text()
    |> IO.iodata_to_binary()
    |> String.trim()
  end

  defp collect_text(el) do
    Enum.flat_map(xmlElement(el, :content), fn
      xmlText() = t -> [:unicode.characters_to_binary(xmlText(t, :value))]
      xmlElement() = child -> collect_text(child)
      _ -> []
    end)
  end

  defp nil_if_blank(""), do: nil
  defp nil_if_blank(s), do: s
end
