# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.UserAgentTest do
  use ExUnit.Case, async: true

  alias VarselWeb.UserAgent

  @chrome "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"
  @edge "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0"
  @safari "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/604.1"
  @firefox "Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0"

  # Every mainstream browser claims to be several others, so the order the
  # tokens are tried in is the whole of what makes this work.
  test "names the browser that is actually running" do
    assert UserAgent.describe(@chrome) == "Chrome on macOS"
    assert UserAgent.describe(@edge) == "Edge on Windows"
    assert UserAgent.describe(@safari) == "Safari on iPhone"
    assert UserAgent.describe(@firefox) == "Firefox on Linux"
  end

  test "falls back to whatever it was given" do
    assert UserAgent.describe("curl/8.7.1") == "curl/8.7.1"
    assert UserAgent.describe(nil) == nil
  end

  test "names the half it recognises" do
    assert UserAgent.describe("Firefox/130.0") == "Firefox"
    assert UserAgent.describe("Mozilla/5.0 (Windows NT 10.0)") == "Windows"
  end
end
