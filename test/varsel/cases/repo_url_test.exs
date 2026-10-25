# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.RepoUrlTest do
  use ExUnit.Case, async: true

  alias Varsel.Cases.RepoUrl

  describe "parse/1" do
    test "detects GitHub and GitLab, and normalizes a .git suffix and trailing slash" do
      assert RepoUrl.parse("https://github.com/acme/widget") ==
               %RepoUrl{host: "github.com", path: "acme/widget", forge: :github}

      assert RepoUrl.parse("https://gitlab.com/group/sub/widget.git/") ==
               %RepoUrl{host: "gitlab.com", path: "group/sub/widget", forge: :gitlab}
    end

    test "an unrecognized host parses as :unknown rather than guessing a shape" do
      assert RepoUrl.parse("https://git.example.com/team/widget") ==
               %RepoUrl{host: "git.example.com", path: "team/widget", forge: :unknown}
    end

    test "forge detection is case-insensitive on the host" do
      assert %RepoUrl{forge: :github} = RepoUrl.parse("https://GitHub.com/acme/widget")
    end

    test "a host with no path normalizes to an empty path" do
      assert RepoUrl.parse("https://git.example.com") ==
               %RepoUrl{host: "git.example.com", path: "", forge: :unknown}
    end
  end

  describe "commit_url/2" do
    @sha "a3253fb4fc7145aeb403537af1c24d3a8d51ffb1"

    test "GitHub commits sit under /commit/" do
      repo = RepoUrl.parse("https://github.com/acme/widget")
      assert RepoUrl.commit_url(repo, @sha) == "https://github.com/acme/widget/commit/#{@sha}"
    end

    test "GitLab commits sit under /-/commit/" do
      repo = RepoUrl.parse("https://gitlab.com/group/widget")
      assert RepoUrl.commit_url(repo, @sha) == "https://gitlab.com/group/widget/-/commit/#{@sha}"
    end

    test "an unknown forge gets no commit URL" do
      repo = RepoUrl.parse("https://git.example.com/team/widget")
      refute RepoUrl.commit_url(repo, @sha)
    end
  end

  describe "label/1" do
    test "a known path renders as owner/repo" do
      assert RepoUrl.label(RepoUrl.parse("https://gitlab.com/group/widget")) == "group/widget"
    end

    test "a host with no path renders as the bare host" do
      assert RepoUrl.label(RepoUrl.parse("https://git.example.com")) == "git.example.com"
    end
  end
end
