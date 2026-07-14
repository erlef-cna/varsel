# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CAPEC.CapecXmlParser do
  @moduledoc """
  Parses the MITRE CAPEC XML catalog (capec_latest.xml) using Erlang's built-in
  `:xmerl_scan`.

  Returns a list of attack pattern maps ready for bulk-upsert into `AttackPattern`.

  Usage:

      {:ok, attack_patterns} = CapecXmlParser.parse(xml_binary)

  Each map has the keys:

      %{
        capec_id:               integer,
        name:                   string,
        abstraction:            atom,
        status:                 atom,
        description:            string,
        extended_description:   string | nil,
        likelihood_of_attack:   atom | nil,
        typical_severity:       atom | nil,
        related_attack_patterns: [%{nature: atom, target_capec_id: integer}],
        related_weaknesses:     [integer],
        prerequisites:          string | nil,
        mitigations:            string | nil,
        consequences:           string | nil
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
  Parses the given XML binary and returns a list of attack pattern maps.

  The XML must be the content of `capec_latest.xml` from the MITRE CAPEC catalog.
  Raises on parse failure.
  """
  @spec parse!(binary()) :: [map()]
  def parse!(xml) when is_binary(xml) do
    {root, _rest} = :xmerl_scan.string(:erlang.binary_to_list(xml), quiet: true)
    extract_attack_patterns(root)
  end

  # ---------------------------------------------------------------------------
  # Private helpers
  # ---------------------------------------------------------------------------

  defp extract_attack_patterns(root) do
    root
    |> child_elements()
    |> Enum.find(&(element_name(&1) == "Attack_Patterns"))
    |> case do
      nil -> []
      patterns_el -> patterns_el |> child_elements() |> Enum.map(&parse_attack_pattern/1)
    end
  end

  defp parse_attack_pattern(el) do
    attrs = attributes_map(el)
    children = child_elements(el)

    %{
      capec_id: String.to_integer(attrs["ID"]),
      name: attrs["Name"],
      abstraction: parse_abstraction(attrs["Abstraction"]),
      status: parse_status(attrs["Status"]),
      description: children |> find_child("Description") |> text_content() |> nil_if_blank(),
      extended_description: children |> find_child("Extended_Description") |> text_content() |> nil_if_blank(),
      likelihood_of_attack: children |> find_child("Likelihood_Of_Attack") |> text_content() |> parse_likelihood(),
      typical_severity: children |> find_child("Typical_Severity") |> text_content() |> parse_severity(),
      related_attack_patterns: parse_related_attack_patterns(children),
      related_weaknesses: parse_related_weakness_ids(children),
      prerequisites: parse_optional_children(children, "Prerequisites", &parse_prerequisites/1),
      mitigations: parse_optional_children(children, "Mitigations", &parse_mitigations/1),
      consequences: parse_optional_children(children, "Consequences", &parse_consequences/1)
    }
  end

  defp parse_related_attack_patterns(children) do
    case find_child(children, "Related_Attack_Patterns") do
      nil -> []
      rel_el -> rel_el |> child_elements() |> Enum.map(&parse_related_attack_pattern/1)
    end
  end

  defp parse_related_weakness_ids(children) do
    case find_child(children, "Related_Weaknesses") do
      nil -> []
      rel_el -> rel_el |> child_elements() |> Enum.map(&parse_related_weakness_id/1)
    end
  end

  defp parse_optional_children(children, name, parser) do
    case find_child(children, name) do
      nil -> nil
      el -> parser.(el)
    end
  end

  defp parse_related_attack_pattern(el) do
    attrs = attributes_map(el)

    %{
      nature: parse_nature(attrs["Nature"]),
      target_capec_id: String.to_integer(attrs["CAPEC_ID"])
    }
  end

  defp parse_related_weakness_id(el) do
    attrs = attributes_map(el)
    String.to_integer(attrs["CWE_ID"])
  end

  defp parse_prerequisites(el) do
    el
    |> child_elements()
    |> Enum.map(fn prereq -> prereq |> text_content() |> nil_if_blank() end)
    |> Enum.reject(&is_nil/1)
    |> Enum.join("\n")
    |> nil_if_blank()
  end

  defp parse_mitigations(el) do
    el
    |> child_elements()
    |> Enum.map(fn mitigation -> mitigation |> text_content() |> nil_if_blank() end)
    |> Enum.reject(&is_nil/1)
    |> Enum.join("\n")
    |> nil_if_blank()
  end

  defp parse_consequences(el) do
    el
    |> child_elements()
    |> Enum.map(fn consequence ->
      children = child_elements(consequence)

      scopes =
        children
        |> Enum.filter(&(element_name(&1) == "Scope"))
        |> Enum.map(&text_content/1)
        |> Enum.reject(&(&1 == ""))

      impact = children |> find_child("Impact") |> text_content() |> nil_if_blank()

      case {scopes, impact} do
        {[], nil} -> nil
        {[], i} -> i
        {s, nil} -> Enum.join(s, ", ")
        {s, i} -> "[#{Enum.join(s, ", ")}] #{i}"
      end
    end)
    |> Enum.reject(&is_nil/1)
    |> Enum.join("\n")
    |> nil_if_blank()
  end

  defp parse_abstraction("Meta"), do: :meta
  defp parse_abstraction("Standard"), do: :standard
  defp parse_abstraction("Detailed"), do: :detailed

  defp parse_status("Stable"), do: :stable
  defp parse_status("Draft"), do: :draft
  defp parse_status("Deprecated"), do: :deprecated
  defp parse_status("Obsolete"), do: :obsolete
  defp parse_status("Usable"), do: :usable

  defp parse_likelihood("High"), do: :high
  defp parse_likelihood("Medium"), do: :medium
  defp parse_likelihood("Low"), do: :low
  defp parse_likelihood(_), do: nil

  defp parse_severity("High"), do: :high
  defp parse_severity("Medium"), do: :medium
  defp parse_severity("Low"), do: :low
  defp parse_severity(_), do: nil

  # Map XML "Nature" attribute strings to our enum atoms
  defp parse_nature("ChildOf"), do: :child_of
  defp parse_nature("ParentOf"), do: :parent_of
  defp parse_nature("CanPrecede"), do: :can_precede
  defp parse_nature("CanFollow"), do: :can_follow
  defp parse_nature("PeerOf"), do: :peer_of
  # Fallback: :peer_of as a safe default for unknown natures
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
