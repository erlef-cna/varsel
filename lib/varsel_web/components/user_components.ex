# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.UserComponents do
  @moduledoc """
  Components that render a user: their picture, their name.
  """

  use Phoenix.Component

  @doc """
  Renders a user as a small filled circle: their picture when one can be
  reached, otherwise a 2-letter initials disc.

  Callers must load `:avatar_url`.
  """
  attr :user, :any, required: true
  attr :variant, :atom, default: :a, values: [:a, :b], doc: "the mock's two avatar color variants"
  attr :class, :any, default: nil

  def avatar_disc(assigns) do
    ~H"""
    <img
      :if={@user.avatar_url}
      src={@user.avatar_url}
      alt=""
      class={["size-[21px] shrink-0 rounded-full object-cover", @class]}
    />
    <span
      :if={!@user.avatar_url}
      class={[
        "inline-flex size-[21px] shrink-0 items-center justify-center rounded-full text-[0.6rem] font-bold",
        avatar_variant_class(@variant),
        @class
      ]}
    >
      {initials(@user)}
    </span>
    """
  end

  defp avatar_variant_class(:a), do: "bg-primary text-primary-content"
  defp avatar_variant_class(:b), do: "bg-secondary text-secondary-content"

  defp initials(%{name: name}) when is_binary(name) and name != "" do
    name
    |> String.split(~r/\s+/, trim: true)
    |> Enum.map(&String.first/1)
    |> Enum.take(2)
    |> Enum.join()
    |> String.upcase()
  end

  defp initials(_user), do: "?"
end
