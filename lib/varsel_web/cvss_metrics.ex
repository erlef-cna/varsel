# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.CvssMetrics do
  @moduledoc """
  Reads the base metrics of a CVSS v3.0, v3.1 or v4.0 vector into named,
  grouped values with a plain-language meaning, for people to read.

  Only the base metrics are read. Threat, environmental and supplemental
  metrics a vector may carry do not change what the vulnerability is.
  """

  @type metric :: %{
          code: String.t(),
          name: String.t(),
          value: String.t(),
          meaning: String.t()
        }
  @type group :: %{title: String.t(), metrics: [metric()]}
  @type breakdown :: %{version: String.t(), groups: [group()]}
  @type change :: %{group: String.t(), name: String.t(), old: String.t(), new: String.t()}

  @attack_vector %{
    "N" => {"Network", "The attacker can reach it remotely, over the network."},
    "A" => {"Adjacent", "The attacker needs access to the same local network or link."},
    "L" => {"Local", "The attacker needs local access, or a user to open something for them."},
    "P" => {"Physical", "The attacker needs to touch the device."}
  }

  @attack_complexity %{
    "L" => {"Low", "The attacker needs no special effort to succeed."},
    "H" => {"High", "The attacker has to defeat security measures, such as address randomization."}
  }

  @attack_requirements %{
    "N" => {"None", "The attack works in every deployment."},
    "P" => {"Present", "The attack works only under specific conditions, such as a race or a configuration."}
  }

  @privileges %{
    "N" => {"None", "The attacker needs no account."},
    "L" => {"Low", "The attacker needs a basic user account."},
    "H" => {"High", "The attacker needs administrative access."}
  }

  @interaction_v4 %{
    "N" => {"None", "No person other than the attacker has to do anything."},
    "P" => {"Passive", "A user has to take part without meaning to, such as by viewing a page."},
    "A" => {"Active", "A user has to take a deliberate action, such as running a file."}
  }

  @interaction_v3 %{
    "N" => {"None", "No person other than the attacker has to do anything."},
    "R" => {"Required", "A user has to take an action for the attack to succeed."}
  }

  @scope %{
    "U" => {"Unchanged", "The impact stays within the vulnerable component."},
    "C" => {"Changed", "The impact reaches components beyond the vulnerable one."}
  }

  @confidentiality %{
    "H" => {"High", "The attacker can read all information."},
    "L" => {"Low", "The attacker can read some information."},
    "N" => {"None", "No information is disclosed."}
  }

  @integrity %{
    "H" => {"High", "The attacker can change any data."},
    "L" => {"Low", "The attacker can change some data."},
    "N" => {"None", "No data can be changed."}
  }

  @availability %{
    "H" => {"High", "The attacker can deny access completely."},
    "L" => {"Low", "The attacker can degrade or interrupt service in part."},
    "N" => {"None", "Availability is not affected."}
  }

  @v4 [
    {"Exploitability",
     [
       {"AV", "Attack Vector", @attack_vector},
       {"AC", "Attack Complexity", @attack_complexity},
       {"AT", "Attack Requirements", @attack_requirements},
       {"PR", "Privileges Required", @privileges},
       {"UI", "User Interaction", @interaction_v4}
     ]},
    {"Vulnerable System",
     [
       {"VC", "Confidentiality", @confidentiality},
       {"VI", "Integrity", @integrity},
       {"VA", "Availability", @availability}
     ]},
    {"Subsequent Systems",
     [
       {"SC", "Confidentiality", @confidentiality},
       {"SI", "Integrity", @integrity},
       {"SA", "Availability", @availability}
     ]}
  ]

  @v3 [
    {"Exploitability",
     [
       {"AV", "Attack Vector", @attack_vector},
       {"AC", "Attack Complexity", @attack_complexity},
       {"PR", "Privileges Required", @privileges},
       {"UI", "User Interaction", @interaction_v3}
     ]},
    {"Impact",
     [
       {"S", "Scope", @scope},
       {"C", "Confidentiality", @confidentiality},
       {"I", "Integrity", @integrity},
       {"A", "Availability", @availability}
     ]}
  ]

  @doc """
  The base metrics of `vector`, grouped. `:error` for anything but a
  complete CVSS v3.0, v3.1 or v4.0 base vector.
  """
  @spec breakdown(String.t() | nil) :: {:ok, breakdown()} | :error
  def breakdown(vector) when is_binary(vector) do
    with {:ok, version, spec, rest} <- version(vector),
         {:ok, pairs} <- pairs(rest),
         {:ok, groups} <- groups(spec, pairs) do
      {:ok, %{version: version, groups: groups}}
    end
  end

  def breakdown(_vector), do: :error

  @doc """
  The base metrics whose value differs between two vectors of the same
  version, in specification order. Empty when either vector does not read,
  or when the versions differ.
  """
  @spec changes(String.t() | nil, String.t() | nil) :: [change()]
  def changes(old, new) do
    with {:ok, %{version: version} = old} <- breakdown(old),
         {:ok, %{version: ^version} = new} <- breakdown(new) do
      for {old_group, new_group} <- Enum.zip(old.groups, new.groups),
          {old_metric, new_metric} <- Enum.zip(old_group.metrics, new_group.metrics),
          old_metric.value != new_metric.value do
        %{
          group: new_group.title,
          name: new_metric.name,
          old: old_metric.value,
          new: new_metric.value
        }
      end
    else
      _unreadable -> []
    end
  end

  defp version("CVSS:4.0/" <> rest), do: {:ok, "4.0", @v4, rest}
  defp version("CVSS:3.1/" <> rest), do: {:ok, "3.1", @v3, rest}
  defp version("CVSS:3.0/" <> rest), do: {:ok, "3.0", @v3, rest}
  defp version(_vector), do: :error

  defp pairs(rest) do
    rest
    |> String.split("/")
    |> Enum.reduce_while({:ok, %{}}, fn part, {:ok, acc} ->
      case String.split(part, ":", parts: 2) do
        [code, value] -> {:cont, {:ok, Map.put(acc, code, value)}}
        _malformed -> {:halt, :error}
      end
    end)
  end

  defp groups(spec, pairs) do
    Enum.reduce_while(spec, {:ok, []}, fn {title, metrics}, {:ok, acc} ->
      case read_metrics(metrics, pairs) do
        {:ok, read} -> {:cont, {:ok, acc ++ [%{title: title, metrics: read}]}}
        :error -> {:halt, :error}
      end
    end)
  end

  defp read_metrics(metrics, pairs) do
    Enum.reduce_while(metrics, {:ok, []}, fn {code, name, values}, {:ok, acc} ->
      case Map.fetch(values, Map.get(pairs, code)) do
        {:ok, {value, meaning}} ->
          {:cont, {:ok, acc ++ [%{code: code, name: name, value: value, meaning: meaning}]}}

        :error ->
          {:halt, :error}
      end
    end)
  end
end
