# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Storybook.Case.GhCommandModal do
  @moduledoc false
  use PhoenixStorybook.Story, :component

  def function, do: &VarselWeb.AdvisoryComponents.gh_command_modal/1

  def layout, do: :one_column

  def container, do: {:div, class: "relative h-[28rem] [&_.modal]:absolute [&_.modal]:z-0"}

  @path "/repos/acme/acme_lib/security-advisories/GHSA-2cfg-hjmp-qrvw"
  @token "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJwdXJwb3NlIjoiZ2l0aHViX21hbnVhbCJ9.c2lnbmF0dXJl"

  defp request(overrides) do
    Map.merge(
      %{
        id: "0b6f6a3e-5d2c-4a4e-9a51-4f0a7f1f2f10",
        operation: :read,
        method: :get,
        path: @path,
        owner: "acme",
        repo: "acme_lib",
        ghsa_id: "GHSA-2cfg-hjmp-qrvw",
        advisory_url: nil,
        fields: nil
      },
      Map.new(overrides)
    )
  end

  defp attributes(overrides) do
    %{request: request(overrides), token: @token, base_url: "https://cna.erlef.org"}
  end

  def variations do
    [
      %Variation{
        id: :link,
        description: "A read whose answer links the advisory: no body, so the command starts at gh.",
        attributes: attributes(advisory_url: "https://github.com/acme/acme_lib/security/advisories/GHSA-2cfg-hjmp-qrvw")
      },
      %Variation{
        id: :pull,
        description: "A read whose answer refreshes the link and pulls the fields named.",
        attributes: attributes(fields: [:title, :weaknesses])
      },
      %Variation{
        id: :push,
        description: "A push: the command fetches the body and sends it with PATCH.",
        attributes: attributes(operation: :push, method: :patch, fields: [:title, :cvss_v4])
      },
      %Variation{
        id: :report,
        description: "A private report: POST to the reports endpoint, with no advisory yet.",
        attributes:
          attributes(
            operation: :report,
            method: :post,
            path: "/repos/acme/acme_lib/security-advisories/reports",
            ghsa_id: nil
          )
      }
    ]
  end
end
