# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Case.LifecycleStepper do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.CaseComponents.lifecycle_stepper/1

  def layout, do: :one_column

  def container, do: {:div, class: "w-full"}

  def variations do
    [
      %Variation{id: :draft, attributes: %{state: :draft}},
      %Variation{id: :review, attributes: %{state: :review}},
      %Variation{id: :approved, attributes: %{state: :approved}},
      %Variation{
        id: :publishing,
        description: "The Published step reads \"Publishing…\" while the job is in flight.",
        attributes: %{state: :publishing}
      },
      %Variation{
        id: :published,
        description: "Every step is done — the terminal happy path.",
        attributes: %{state: :published}
      },
      %Variation{
        id: :closed,
        description: "A closed case has no pipeline; it shows a terminal pill instead.",
        attributes: %{state: :closed}
      }
    ]
  end
end
