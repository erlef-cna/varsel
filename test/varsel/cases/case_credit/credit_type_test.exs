# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.CaseCredit.CreditTypeTest do
  use ExUnit.Case, async: true

  alias Varsel.Cases.CaseCredit.CreditType

  test "render/1 spells a type as CVE JSON does" do
    assert CreditType.render(:remediation_developer) == "remediation developer"
    assert CreditType.render(:finder) == "finder"
  end

  describe "weightiest/1" do
    test "writing the fix outweighs finding it, and finding it outweighs the rest" do
      assert CreditType.weightiest([:finder, :remediation_developer]) == :remediation_developer
      assert CreditType.weightiest([:sponsor, :finder, :coordinator]) == :finder
      assert CreditType.weightiest([:reporter, :analyst]) == :reporter
      assert CreditType.weightiest([:tool, :other]) == :tool
    end

    test "one role stands for itself, whatever the order given" do
      assert CreditType.weightiest([:other]) == :other
      assert CreditType.weightiest([:analyst, :reporter, :finder]) == :finder
    end

    test "every value has a place in the precedence" do
      for type <- CreditType.values() do
        assert CreditType.weightiest([type, :other]) == type
      end
    end
  end
end
