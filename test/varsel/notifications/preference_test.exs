# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Notifications.PreferenceTest do
  use Varsel.DataCase, async: true

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

    test "defaults to both channels off for an opt-in kind" do
      assert %Preference{kind: :unassigned_review_requested, in_app: false, email: false} =
               Preference.for_kind([], :unassigned_review_requested)
    end
  end
end
