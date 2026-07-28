# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Derivation.PinnedTransportTest do
  use ExUnit.Case, async: false

  alias Varsel.Cases.Derivation.PinnedTransport
  alias Varsel.Test.StubResolver

  @public {93, 184, 216, 34}

  setup do
    previous = Application.get_env(:varsel, :dns_resolver)
    Application.put_env(:varsel, :dns_resolver, StubResolver)

    on_exit(fn ->
      StubResolver.clear()

      if previous,
        do: Application.put_env(:varsel, :dns_resolver, previous),
        else: Application.delete_env(:varsel, :dns_resolver)
    end)

    :ok
  end

  describe "pinning" do
    setup do
      StubResolver.stub(%{"forge.example" => [@public]})
    end

    test "the URL carries the address, and the name is kept for Host, SNI and the certificate" do
      assert {:ok, transport} = PinnedTransport.build("https://forge.example/acme/pkg.git")

      assert %URI{host: "93.184.216.34"} = URI.new!(transport.url)

      # Mint takes every *name* from :hostname — the Host header, the TLS
      # server name, and the name the certificate is checked against.
      assert transport.connect_options[:hostname] == "forge.example"
      assert transport.connect_options[:transport_opts][:customize_hostname_check][:match_fun]

      # The rest of the URL has to survive, or we would clone the wrong repo.
      assert String.ends_with?(transport.url, "/acme/pkg.git")
    end

    test "a non-default port is preserved" do
      assert {:ok, transport} = PinnedTransport.build("https://forge.example:8443/acme/pkg.git")
      assert %URI{port: 8443, host: "93.184.216.34"} = URI.new!(transport.url)
      assert transport.connect_options[:hostname] == "forge.example"
    end

    test "redirects stay off, so there is no second hop to re-resolve" do
      assert {:ok, transport} = PinnedTransport.build("https://forge.example/acme/pkg.git")
      assert transport.redirect == false
    end

    test "an IPv6 answer is bracketed in the URL" do
      StubResolver.stub(%{
        "v6.example" => [{0x2606, 0x2800, 0x220, 1, 0x248, 0x1893, 0x25C8, 0x1946}]
      })

      assert {:ok, transport} = PinnedTransport.build("https://v6.example/acme/pkg.git")

      # Bracketed in the URL itself, as an IPv6 host must be.
      assert transport.url == "https://[2606:2800:220:1:248:1893:25c8:1946]/acme/pkg.git"
      assert transport.connect_options[:hostname] == "v6.example"
    end
  end

  # The reason this module exists: the save-time check saw a public address,
  # and by the time the clone runs the name answers with a private one.
  test "a host that rebinds to a private address between lookups is refused at clone time" do
    StubResolver.stub(%{"rebind.example" => [[@public], [{127, 0, 0, 1}]]})

    assert {:ok, _first} = PinnedTransport.build("https://rebind.example/acme/pkg.git")

    assert {:error, :private_address} =
             PinnedTransport.build("https://rebind.example/acme/pkg.git")
  end

  # Answering with one public and one private address must not let the private
  # one through on a later connection.
  test "a host answering with any private address is refused" do
    StubResolver.stub(%{"mixed.example" => [[@public, {10, 0, 0, 1}]]})

    assert {:error, :private_address} =
             PinnedTransport.build("https://mixed.example/acme/pkg.git")
  end

  describe "http" do
    setup do
      StubResolver.stub(%{"forge.example" => [@public]})
    end

    test "is pinned to the checked address, like https" do
      assert {:ok, transport} = PinnedTransport.build("http://forge.example/acme/pkg.git")

      assert %URI{scheme: "http", host: "93.184.216.34"} = URI.new!(transport.url)
      assert transport.connect_options[:hostname] == "forge.example"
    end

    test "is refused when the host resolves privately" do
      assert {:error, :private_address} = PinnedTransport.build("http://127.0.0.1/acme/pkg.git")
    end
  end

  describe "refusals" do
    test "an address literal in a private range is refused without a lookup" do
      for url <- [
            "https://127.0.0.1/acme/pkg.git",
            "https://[::1]/acme/pkg.git",
            "https://10.0.0.1/acme/pkg.git",
            "https://192.168.1.1/acme/pkg.git",
            "https://169.254.169.254/latest/meta-data",
            "https://[::ffff:127.0.0.1]/acme/pkg.git"
          ] do
        assert {:error, :private_address} = PinnedTransport.build(url), "expected #{url} refused"
      end
    end

    test "a host that resolves to nothing is refused rather than dialled by name" do
      assert {:error, :unresolvable} =
               PinnedTransport.build("https://nowhere.example/acme/pkg.git")
    end

    test "anything but https/http is refused" do
      for url <- [
            "file:///etc/passwd",
            "git://forge.example/acme/pkg.git",
            "ssh://forge.example/acme/pkg.git",
            "not a url",
            # A scheme with no host has nothing to resolve or pin to.
            "https:///acme/pkg.git"
          ] do
        assert {:error, :invalid_url} = PinnedTransport.build(url), "expected #{url} refused"
      end
    end
  end
end
