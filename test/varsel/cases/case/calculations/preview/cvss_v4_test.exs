# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Case.Calculations.Preview.CvssV4Test do
  use ExUnit.Case, async: true

  alias Varsel.Cases.Case.Calculations.Preview.CvssV4
  alias Varsel.Types.CVSS

  defp expand(vector) do
    {:ok, cvss} = Ash.Type.cast_input(CVSS, vector, [])
    CvssV4.expand(cvss)
  end

  test "an integral base score renders as a JSON integer" do
    assert %{"baseScore" => 10} =
             expand("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H")
  end

  test "a fractional base score renders as a float" do
    assert %{"baseScore" => 9.3} =
             expand("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")
  end
end
