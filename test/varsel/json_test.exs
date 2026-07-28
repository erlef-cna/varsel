# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.JSONTest do
  use ExUnit.Case, async: true

  alias Elixir.JSON.DecodeError
  alias Varsel.JSON

  describe "decode!/1 with a binary" do
    test "decodes a document" do
      assert JSON.decode!(~s({"a":[1,2],"b":"x"})) == %{"a" => [1, 2], "b" => "x"}
    end

    test "decodes null as nil" do
      assert JSON.decode!(~s({"a":null})) == %{"a" => nil}
    end

    test "raises on a malformed document" do
      assert_raise DecodeError, fn -> JSON.decode!(~s({"a":)) end
    end
  end

  describe "decode!/1 with a stream" do
    test "decodes a document split across chunks" do
      chunks = [~s({"a":[1,), ~s(2],"b":), ~s("x"})]

      assert JSON.decode!(chunks) == %{"a" => [1, 2], "b" => "x"}
    end

    test "decodes a document arriving in one chunk" do
      assert JSON.decode!([~s({"a":1})]) == %{"a" => 1}
    end

    test "decodes null as nil, like the binary mode" do
      assert JSON.decode!([~s({"a":), ~s(null})]) == %{"a" => nil}
    end

    test "splitting mid-token does not change the result" do
      json = ~s({"results":[{"errorCode":"E003","errorPath":""}]})
      chunks = for <<chunk::binary-size(1) <- json>>, do: chunk

      assert JSON.decode!(chunks) == JSON.decode!(json)
    end

    test "ignores chunks arriving after the document ends" do
      assert JSON.decode!([~s({"a":1}), "\n"]) == %{"a" => 1}
    end

    test "raises when the document ends early" do
      assert_raise DecodeError, fn -> JSON.decode!([~s({"a":)]) end
    end

    test "raises on a malformed document" do
      assert_raise DecodeError, fn -> JSON.decode!([~s({"a" 1})]) end
    end

    test "raises on an empty stream" do
      assert_raise DecodeError, fn -> JSON.decode!([]) end
    end

    test "the error points at the offending byte in the chunk that failed" do
      error =
        assert_raise DecodeError, fn -> JSON.decode!([~s({"a":), ~s(&1})]) end

      assert error.data == ~s(&1})
      assert error.offset == 0
      assert error.message =~ "invalid byte 38"
    end
  end
end
