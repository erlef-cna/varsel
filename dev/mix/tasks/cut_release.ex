# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Mix.Tasks.CutRelease do
  @shortdoc "Bumps the version, commits, and creates a signed release tag"

  @moduledoc """
  Prepares a release: sets the version everywhere it is declared, commits the
  change, and creates a signed tag.

  The task shows the diff and asks for confirmation before it writes. It does
  not push.

  Usage:

      mix cut_release 0.12.0
      mix cut_release 0.12.0 --dry-run
  """

  use Mix.Task

  alias Igniter.Project.MixProject

  @json_files [
    ".claude-plugin/plugin.json",
    ".claude-plugin/marketplace.json",
    "assets/package.json"
  ]

  @changed_files ["mix.exs", "assets/package-lock.json" | @json_files]

  @impl Mix.Task
  def run(args) do
    {opts, [version]} = OptionParser.parse!(args, strict: [dry_run: :boolean])
    tag = "v#{version}"

    ensure_clean_tree!()
    ensure_new_tag!(tag)

    {:ok, _apps} = Application.ensure_all_started(:rewrite)

    result =
      Igniter.new()
      |> bump_version(version)
      |> Igniter.do_or_dry_run(title: "Release #{tag}", dry_run: opts[:dry_run])

    case result do
      :changes_made -> commit_and_tag!(tag)
      :dry_run_with_changes -> :ok
      other -> Mix.raise("Release #{tag} stopped before the commit: #{inspect(other)}")
    end
  end

  @doc false
  @spec bump_version(Igniter.t(), String.t()) :: Igniter.t()
  def bump_version(igniter, version) do
    igniter
    |> MixProject.update(:project, [:version], fn _zipper ->
      {:ok, {:code, inspect(version)}}
    end)
    |> set_json_versions(version)
  end

  defp set_json_versions(igniter, version) do
    Enum.reduce(@json_files, igniter, &set_json_version(&2, &1, version))
  end

  defp ensure_clean_tree! do
    if git!(["status", "--porcelain"]) != "" do
      Mix.raise("The working tree has changes. Commit or stash them first.")
    end
  end

  defp ensure_new_tag!(tag) do
    if git!(["tag", "--list", tag]) != "" do
      Mix.raise("The tag #{tag} exists.")
    end
  end

  defp set_json_version(igniter, path, version) do
    Igniter.update_file(igniter, path, fn source ->
      Rewrite.Source.update(source, :content, fn content ->
        content
        |> Jason.decode!(objects: :ordered_objects)
        |> put_versions(path, version)
        |> Jason.encode!(pretty: true)
        |> Kernel.<>("\n")
      end)
    end)
  end

  defp put_versions(json, ".claude-plugin/marketplace.json", version) do
    update_in(json["plugins"], fn plugins ->
      Enum.map(plugins, &put_in(&1["version"], version))
    end)
  end

  defp put_versions(json, _path, version), do: put_in(json["version"], version)

  defp commit_and_tag!(tag) do
    cmd!("npm", ["install", "--package-lock-only"], cd: "assets")
    cmd!("git", ["add" | @changed_files])
    cmd!("git", ["commit", "-m", "Release #{tag}"])
    cmd!("git", ["tag", "-s", tag, "-m", tag])

    Mix.shell().info("Created #{tag}. Push with: git push --follow-tags")
  end

  defp git!(args) do
    case System.cmd("git", args, stderr_to_stdout: true) do
      {output, 0} ->
        String.trim(output)

      {output, status} ->
        Mix.raise("git #{Enum.join(args, " ")} exited with #{status}: #{output}")
    end
  end

  defp cmd!(command, args, opts \\ []) do
    case System.cmd(command, args, [into: IO.stream(), stderr_to_stdout: true] ++ opts) do
      {_output, 0} -> :ok
      {_output, status} -> Mix.raise("#{command} #{Enum.join(args, " ")} exited with #{status}")
    end
  end
end
