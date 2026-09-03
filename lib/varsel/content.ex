# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Content do
  @moduledoc """
  The static content pages under `priv/pages`, compiled into the module.

  A page is listed here by filename. That list is one of the places a new page
  has to be registered; the others are the `router.ex` page list,
  `static_pages` in `sitemap_controller.ex`, the nav and footer in
  `layouts.ex`, and the rendering list in `site_pages_test.exs`.
  """

  use Varsel.Content.Compiler

  page "api-access.md"
  page "common-weaknesses.md"
  page "contact.md"
  page "coordinator-process.md"
  page "cve-criteria.md"
  page "data-licensing.md"
  page "guide.md"
  page "guide-affected-versions.md"
  page "guide-ai-tooling.md"
  page "guide-filing-a-case.md"
  page "guide-record-conventions.md"
  page "guide-review-and-publication.md"
  page "maintainer-process.md"
  page "privacy-policy.md"
  page "scope.md"
  page "security-policy.md"
  page "terms-and-conditions.md"
end
