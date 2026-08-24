# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Notifications.PreferenceTest do
  use Varsel.DataCase, async: false

  alias Varsel.Notifications.Preference

  describe "for_kind/2" do
    test "returns the matching preference when present" do
      preferences = [
        %Preference{kind: :comment_posted, in_app: false, email: true}
      ]

      assert %Preference{kind: :comment_posted, in_app: false, email: true} =
               Preference.for_kind(preferences, :comment_posted)
    end

    test "defaults to both channels on for a kind absent from the list" do
      assert %Preference{kind: :case_assigned, in_app: true, email: true} =
               Preference.for_kind([], :case_assigned)
    end
  end
end
