# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.ChildParams do
  @moduledoc """
  Translates the case workspace's child forms into attributes their resources
  accept.

  The forms carry values in the shapes an HTML input can produce — comma
  separated text standing in for a list, `"key=value"` pairs for a map, a
  datalist label carrying the id it was picked from — so each has to be read
  back before it reaches a changeset. Which fields need it depends on the
  child type, hence the type argument threaded through.
  """

  # Comma/newline separated text inputs that become {:array, :string} attributes.
  @list_params %{
    "package" => ~w(platforms),
    "package_otp" => ~w(applications fixed_commits),
    "package_elixir" => ~w(applications fixed_commits),
    "package_gleam" => ~w(fixed_commits),
    "channel" => ~w(tag_suffixes),
    "reference" => ~w(tags)
  }

  # The package modal types sharing the program-files textarea.
  @package_types ~w(package package_otp package_elixir package_gleam)

  @doc """
  Reads one child form's params back into resource attributes, merging in the
  `parent` ids the form itself does not carry.
  """
  @spec normalize(String.t(), map(), map()) :: map()
  def normalize(type, params, parent) do
    params =
      params
      |> Map.merge(parent)
      |> merge_reference_tags(type)
      |> parse_classification_id(type)
      |> parse_qualifiers(type)
      |> parse_program_files(type)

    Enum.reduce(Map.get(@list_params, type, []), params, fn key, params ->
      case params[key] do
        value when is_binary(value) ->
          Map.put(params, key, split_list(value))

        _other ->
          params
      end
    end)
  end

  @doc """
  The nested program-file rows in their canonical stored shape: ordered by
  index, internal form-tracking keys and pathless (just-added, empty) rows
  dropped. Used where params leave the form machinery — proposal payloads
  and the projected-row diff.
  """
  @spec program_files_list(map()) :: [map()]
  def program_files_list(%{} = files) do
    files
    |> Enum.sort_by(fn {index, _file} -> String.to_integer(index) end)
    |> Enum.map(fn {_index, file} ->
      %{
        "path" => file["path"],
        "modules" => file["modules"] || [],
        "routines" => file["routines"] || []
      }
    end)
    |> Enum.reject(&(&1["path"] in [nil, ""]))
  end

  @doc "Splits one comma/newline separated text input into its values."
  @spec split_list(String.t()) :: [String.t()]
  def split_list(value) do
    value
    |> String.split(~r/[\n,]/, trim: true)
    |> Enum.map(&String.trim/1)
    |> Enum.reject(&(&1 == ""))
  end

  # Program files come from nested forms as an indexed map of rows; the
  # module/routine text inputs within each row are comma separated. The
  # indexed-map shape stays as-is for AshPhoenix's nested-form tracking.
  defp parse_program_files(%{"program_files" => %{} = files} = params, type) when type in @package_types do
    files =
      Map.new(files, fn {index, file} ->
        {index, file |> split_file_list("modules") |> split_file_list("routines")}
      end)

    Map.put(params, "program_files", files)
  end

  defp parse_program_files(params, _type), do: params

  defp split_file_list(file, key) do
    case file[key] do
      value when is_binary(value) -> Map.put(file, key, split_list(value))
      _other -> file
    end
  end

  # Channel qualifiers arrive as "key=value, key=value" text.
  defp parse_qualifiers(%{"qualifiers" => value} = params, "channel") when is_binary(value) do
    qualifiers =
      value
      |> split_list()
      |> Enum.flat_map(fn pair ->
        case String.split(pair, "=", parts: 2) do
          [key, value] -> [{String.trim(key), String.trim(value)}]
          _no_value -> []
        end
      end)
      |> Map.new()

    Map.put(params, "qualifiers", qualifiers)
  end

  defp parse_qualifiers(params, _type), do: params

  # The classification inputs autocomplete to "CWE-613 Insufficient Session
  # Expiration"-style datalist values; extract the numeric id (bare numbers
  # keep working too).
  defp parse_classification_id(params, "weakness"), do: extract_numeric_id(params, "cwe_id")
  defp parse_classification_id(params, "impact"), do: extract_numeric_id(params, "capec_id")
  defp parse_classification_id(params, _type), do: params

  defp extract_numeric_id(params, key) do
    with value when is_binary(value) <- params[key],
         [digits] <- Regex.run(~r/\d+/, value) do
      Map.put(params, key, digits)
    else
      _no_number -> params
    end
  end

  # Reference tags arrive as a checkbox list (with an empty sentinel) plus a
  # comma-separated custom_tags text input; merge them into one tags list.
  defp merge_reference_tags(params, "reference") do
    standard = params |> Map.get("tags", []) |> List.wrap() |> Enum.reject(&(&1 == ""))
    custom = split_list(params["custom_tags"] || "")

    params
    |> Map.put("tags", Enum.uniq(standard ++ custom))
    |> Map.delete("custom_tags")
  end

  defp merge_reference_tags(params, _type), do: params
end
