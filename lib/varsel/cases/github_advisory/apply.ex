# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.GitHubAdvisory.Apply do
  @moduledoc """
  Writes what an advisory states onto a case, through the case's own child
  actions as the actor, so the validations and policies that apply to adding
  a row by hand apply here too.

  Used when a case is opened from an advisory and when a linked case pulls
  from one. The rows come from `Varsel.Cases.GitHubAdvisory.Import`. This
  module drops the CWEs the catalog does not know, names a credit by its
  GitHub handle alone, and knows which action creates each kind of package.
  """

  alias Varsel.Cases
  alias Varsel.Cases.AffectedPackage.Preset
  alias Varsel.Cases.Case
  alias Varsel.Cases.CaseMetric
  alias Varsel.Cases.GitHubAdvisory.Import
  alias Varsel.CWE.Weakness

  require Ash.Query

  @type opts :: keyword()
  @type written :: {:ok, struct()} | {:error, term()}

  @doc """
  The CaseWeakness rows among `rows` whose CWE the local catalog knows. A CWE
  it does not know is dropped before the insert, since the foreign key would
  refuse the whole write with it.
  """
  @spec known_weaknesses([map()]) :: [map()]
  def known_weaknesses([]), do: []

  def known_weaknesses(rows) do
    ids = Enum.map(rows, & &1.cwe_id)

    present =
      Weakness
      |> Ash.Query.filter(cwe_id in ^ids)
      |> Ash.Query.select([:cwe_id])
      |> Ash.read!()
      |> MapSet.new(& &1.cwe_id)

    Enum.filter(rows, &MapSet.member?(present, &1.cwe_id))
  end

  @doc "Adds one of the advisory's `Import.child_params/1` metrics to the case."
  @spec add_metric(map(), Ash.UUID.t(), opts()) :: written()
  def add_metric(row, case_id, opts) do
    Cases.add_case_metric(Map.put(row, :case_id, case_id), opts)
  end

  @doc """
  Sets the case's GENERAL score to `vector`: edits the GENERAL metric the
  case has, or adds one.
  """
  @spec put_general_metric(String.t(), Case.t(), opts()) :: written()
  def put_general_metric(vector, %Case{general_metric: %CaseMetric{} = metric}, opts) do
    Cases.edit_case_metric(metric, %{cvss_v4: vector}, opts)
  end

  def put_general_metric(vector, %Case{id: case_id}, opts) do
    Cases.add_case_metric(
      %{case_id: case_id, scenario: CaseMetric.general_scenario(), cvss_v4: vector},
      opts
    )
  end

  @doc "Adds one of `known_weaknesses/1` to the case."
  @spec add_weakness(map(), Ash.UUID.t(), opts()) :: written()
  def add_weakness(row, case_id, opts) do
    Cases.add_case_weakness(Map.put(row, :case_id, case_id), opts)
  end

  @doc """
  CaseCredit rows for the advisory's credits: the GitHub handle and the
  roles. The credit's own action names the person from the handle
  (`Varsel.Cases.CaseCredit.Changes.ResolveCreditedUser`).
  """
  @spec credit_rows([Import.credit()]) :: [map()]
  def credit_rows(credits) do
    for credit <- credits do
      %{
        handles: [%{strategy: :github, username: credit.login}],
        credit_types: credit.credit_types
      }
    end
  end

  @doc "Adds one of `credit_rows/1` to the case."
  @spec add_credit(map(), Ash.UUID.t(), opts()) :: written()
  def add_credit(row, case_id, opts) do
    Cases.add_case_credit(Map.put(row, :case_id, case_id), opts)
  end

  @doc """
  Creates one of the advisory's affected packages on the case: through its
  preset when it has one, else as a plain package followed by its channels.
  A preset that takes applications and is given none stands as the preset's
  product with the repository channel alone, for a person to complete.
  """
  @spec add_package(Import.affected_package(), Ash.UUID.t(), opts()) :: written()
  def add_package(package, case_id, opts)

  def add_package(%{preset: preset, applications: []}, case_id, opts) when not is_nil(preset) do
    if Preset.applications?(preset) do
      preset
      |> Preset.attributes()
      |> Map.put(:case_id, case_id)
      |> Cases.add_affected_package(opts)
    else
      add_preset(preset, %{case_id: case_id}, opts)
    end
  end

  def add_package(%{preset: preset, applications: applications}, case_id, opts) when not is_nil(preset) do
    add_preset(preset, %{case_id: case_id, applications: applications}, opts)
  end

  def add_package(%{attributes: attributes, channels: channels}, case_id, opts) do
    with {:ok, package} <-
           Cases.add_affected_package(Map.put(attributes, :case_id, case_id), opts),
         :ok <- add_channels(channels, package, opts) do
      {:ok, package}
    end
  end

  @doc "Adds each of `rows` with `add`, stopping at the first refusal."
  @spec each([term()], (term() -> written())) :: :ok | {:error, term()}
  def each(rows, add) do
    Enum.reduce_while(rows, :ok, fn row, :ok ->
      case add.(row) do
        {:ok, _written} -> {:cont, :ok}
        {:error, error} -> {:halt, {:error, error}}
      end
    end)
  end

  defp add_channels(channels, package, opts) do
    each(channels, fn channel ->
      channel
      |> Map.merge(%{case_id: package.case_id, affected_package_id: package.id})
      |> Cases.add_package_channel(opts)
    end)
  end

  defp add_preset(:otp, attrs, opts), do: Cases.add_otp_affected_package(attrs, opts)
  defp add_preset(:elixir, attrs, opts), do: Cases.add_elixir_affected_package(attrs, opts)
  defp add_preset(:gleam, attrs, opts), do: Cases.add_gleam_affected_package(attrs, opts)
end
