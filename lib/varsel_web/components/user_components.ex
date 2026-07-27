# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.UserComponents do
  @moduledoc """
  Components that render a user: their picture, their name.
  """

  use Phoenix.Component

  @doc """
  Renders the name a user goes by, including when there is no user.

  A deleted account leaves its comments, proposals and reports behind with
  nothing attached, so `nil` is an ordinary case here rather than an error: it
  says the account is gone, which is not the same as a name being withheld.
  """
  attr :user, :any, required: true
  attr :class, :any, default: nil

  def user_name(assigns) do
    ~H"""
    <span class={[@user == nil && "italic text-base-content/50", @class]}>{name_of(@user)}</span>
    """
  end

  defp name_of(nil), do: "Deleted user"
  defp name_of(%{name: name}) when is_binary(name) and name != "", do: name
  defp name_of(_user), do: "(hidden)"

  @doc """
  Renders a user as their picture followed by their name — the usual way one
  appears beside something they did.

  Callers must load `:avatar_url`.
  """
  attr :user, :any, required: true
  attr :variant, :atom, default: :a, values: [:a, :b], doc: "the mock's two avatar color variants"
  attr :class, :any, default: nil
  attr :name_class, :any, default: nil

  def user_badge(assigns) do
    ~H"""
    <span class={["inline-flex items-center gap-1.5", @class]}>
      <.avatar_disc user={@user} variant={@variant} />
      <.user_name user={@user} class={@name_class} />
    </span>
    """
  end

  @doc """
  Renders a user as a small filled circle: their picture when one can be
  reached, otherwise a 2-letter initials disc.

  Callers must load `:avatar_url`, and `:display_name` for the initials to
  read as the account menu's label does.
  """
  attr :user, :any, required: true
  attr :variant, :atom, default: :a, values: [:a, :b], doc: "the mock's two avatar color variants"
  attr :class, :any, default: nil

  def avatar_disc(%{user: nil} = assigns) do
    ~H"""
    <span
      class={[
        "inline-flex size-[21px] shrink-0 items-center justify-center rounded-full text-[0.6rem] font-bold",
        "bg-base-300 text-base-content/50",
        @class
      ]}
      title="Deleted user"
    >
      —
    </span>
    """
  end

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

  # `display_name` first: it is what the account menu shows, and it falls back
  # to a provider handle for the users who never set a name of their own.
  defp initials(user) do
    case Enum.find([:display_name, :name], &present?(Map.get(user, &1))) do
      nil -> "?"
      key -> user |> Map.fetch!(key) |> to_initials()
    end
  end

  defp present?(value), do: is_binary(value) and value != ""

  defp to_initials(name) do
    name
    |> String.split(~r/\s+/, trim: true)
    |> Enum.map(&String.first/1)
    |> Enum.take(2)
    |> Enum.join()
    |> String.upcase()
  end
end
