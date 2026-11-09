# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Comment.MentionsTest do
  use ExUnit.Case, async: true

  alias Varsel.Cases.Comment.Mentions

  @jane "0190c0de-0000-7000-8000-00000000000a"
  @bob "0190c0de-0000-7000-8000-00000000000b"

  test "a token is a mention link that drops the brackets a name would break" do
    assert Mentions.token(@jane, "Jane [EEF]") == "[@Jane EEF](mention:#{@jane})"
  end

  test "reads each mentioned id once, in order, and nothing from code" do
    body = """
    #{Mentions.token(@bob, "Bob")} and #{Mentions.token(@jane, "Jane")}, again
    [@Bob](mention:#{String.upcase(@bob)}).

    `#{Mentions.token("0190c0de-0000-7000-8000-00000000000c", "Code")}`

    [@Nobody](mention:not-a-uuid) [a link](https://example.com)
    """

    assert Mentions.user_ids(body) == [@bob, @jane]
  end

  test "writes each mention as the name it carries" do
    assert Mentions.to_names("Hi #{Mentions.token(@jane, "Jane Doe")}!") == "Hi **Jane Doe**!"
  end
end
