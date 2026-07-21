# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Xml do
  @moduledoc """
  SAX-based lazy helpers for parsing large XML catalogs.

  `stream_subtrees/3` transforms a stream of binary chunks into a stream of
  subtree nodes, materializing only one matching subtree at a time — the full
  document never exists as an in-memory tree (a ~60MB catalog blew past 1GB as
  an xmerl charlist DOM and OOM-killed the VM).

  Subtree nodes are `{name, attributes_map, children}` tuples where children
  are nested nodes or text binaries, in document order.
  """

  @type xml_node :: {String.t(), %{String.t() => String.t()}, [xml_node() | binary()]}

  @doc """
  Transforms a stream of XML binary chunks into a lazy stream of subtree nodes
  for every `element` whose direct parent is `container`, in document order.

  Raises `Saxy.ParseError` on malformed input when the stream is run.
  """
  @spec stream_subtrees(Enumerable.t(binary()), String.t(), String.t()) ::
          Enumerable.t(xml_node())
  def stream_subtrees(chunks, container, element) do
    chunks
    |> Saxy.stream_events()
    |> Stream.transform({[], nil}, fn event, {path, stack} ->
      collect_subtree(event, path, stack, container, element)
    end)
  end

  @doc """
  Splits a binary into `chunk_size`-byte sub-binaries for `stream_subtrees/3`.

  Feeding one huge chunk would make `Saxy.stream_events/2` emit every event of
  the document in a single batch, undoing the streaming memory bound.
  """
  @spec chunk_binary(binary(), pos_integer()) :: Enumerable.t(binary())
  def chunk_binary(binary, chunk_size \\ 65_536) when is_binary(binary) do
    {:ok, device} = StringIO.open(binary)
    IO.binstream(device, chunk_size)
  end

  defp collect_subtree({:start_element, {name, attributes}}, path, nil, container, element) do
    if name == element and List.first(path) == container do
      {[], {path, [{name, Map.new(attributes), []}]}}
    else
      {[], {[name | path], nil}}
    end
  end

  defp collect_subtree({:start_element, {name, attributes}}, path, stack, _container, _element) do
    {[], {path, [{name, Map.new(attributes), []} | stack]}}
  end

  defp collect_subtree({:end_element, _name}, path, nil, _container, _element) do
    {[], {tl(path), nil}}
  end

  defp collect_subtree({:end_element, _name}, path, [{name, attrs, children}], _c, _e) do
    {[{name, attrs, Enum.reverse(children)}], {path, nil}}
  end

  defp collect_subtree({:end_element, _name}, path, [top, parent | rest], _c, _e) do
    {name, attrs, children} = top
    {parent_name, parent_attrs, parent_children} = parent
    node = {name, attrs, Enum.reverse(children)}
    {[], {path, [{parent_name, parent_attrs, [node | parent_children]} | rest]}}
  end

  defp collect_subtree({text_event, chars}, path, [{name, attrs, children} | rest], _c, _e)
       when text_event in [:characters, :cdata] do
    {[], {path, [{name, attrs, [chars | children]} | rest]}}
  end

  defp collect_subtree(_event, path, stack, _container, _element), do: {[], {path, stack}}

  @doc "Returns the element children of a node (text nodes filtered out)."
  @spec child_elements(xml_node() | nil) :: [xml_node()]
  def child_elements(nil), do: []
  def child_elements({_name, _attrs, children}), do: Enum.filter(children, &is_tuple/1)

  @spec element_name(xml_node()) :: String.t()
  def element_name({name, _attrs, _children}), do: name

  @spec find_child([xml_node()], String.t()) :: xml_node() | nil
  def find_child(children, name) when is_list(children) do
    Enum.find(children, &(element_name(&1) == name))
  end

  @spec attributes(xml_node()) :: %{String.t() => String.t()}
  def attributes({_name, attrs, _children}), do: attrs

  @doc "Recursively concatenated text content of a node, trimmed."
  @spec text_content(xml_node() | nil) :: String.t()
  def text_content(nil), do: ""

  def text_content({_name, _attrs, children}) do
    children
    |> collect_text()
    |> IO.iodata_to_binary()
    |> String.trim()
  end

  defp collect_text(children) do
    Enum.map(children, fn
      text when is_binary(text) -> text
      {_name, _attrs, nested} -> collect_text(nested)
    end)
  end
end
