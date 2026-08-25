# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Description.AffectedSummary do
  @moduledoc """
  Builds the "This issue affects …" sentence appended to every published
  description, from the record's own `affected[]`.

  The sentence restates the versions block in prose. Deriving it rather than
  asking an author to type it is the point: the two can then never disagree, and
  a version change rewrites the sentence for free.

  ## Shapes

      This issue affects plug: from 0.1.0 before 1.16.6.
      This issue affects plug: from 0.1.0 before 1.16.6, and from 1.17.0 before 1.17.4.
      This issue affects bandit: before 1.11.0.
      This issue affects earmark: from 1.4.1 onward.
      This issue affects hex_core: from 0.1.0 before 0.12.1; hex: from 2.3.0 before 2.3.2.

  A range fixed on several release lines carries its fixes as `changes[]` rather
  than one upper bound, and the sentence names every one:

      This issue affects OTP: from 27.0 before 27.3.4.15, 28.5.0.4, and 29.0.4.

  Erlang/OTP names the release and the application together, since a reader
  knows one or the other but the advisory concerns both:

      This issue affects OTP from OTP 17.0 before OTP 28.0.3, corresponding to
      ssh from 3.0.1 before 5.3.3.

  ## What is left out

    * Rows that are not `status: "affected"`. An `unknown` row says the record
      does not know, which "this issue affects" would misreport as certainty.
    * Commit-versioned entries, when the same product is also described by
      version — the commit range is the same fact in a vocabulary the sentence
      cannot read aloud. A product known ONLY by commit keeps them, since that
      is all there is to say.
    * OCI entries, on the same grounds: an image tag restates the release
      version, once per tag flavor, so a ten-flavor channel would otherwise
      repeat one range ten times.

  ## Non-breaking spaces

  A version containing whitespace must not wrap mid-version, so its spaces are
  bound with U+00A0 — including the one in an OTP release's `OTP ` prefix, which
  reads as part of the version. The markdown renderer turns those into `&nbsp;`
  for the HTML representation on its own, so only the one encoding is produced
  here.
  """

  @doc """
  The sentence for a rendered `affected[]`, or `nil` when nothing can be said.

  Pass the same `affected[]` the record publishes — the sentence is a reading of
  that list, not a second derivation from the case.
  """
  @spec summarize([map()]) :: String.t() | nil
  def summarize(affected) when is_list(affected) do
    [affected_sentence(affected), unknown_sentence(affected)]
    |> Enum.reject(&is_nil/1)
    |> case do
      [] -> nil
      sentences -> Enum.join(sentences, " ")
    end
  end

  defp affected_sentence(affected) do
    case affected |> entries("affected") |> clauses() do
      [] -> nil
      clauses -> "This issue affects " <> Enum.join(clauses, "; ") <> "."
    end
  end

  # Its own sentence, never folded into the one above: "this issue affects" is a
  # claim of certainty, and an `unknown` row is the record saying it has none.
  # Left out of the summary entirely it would read as "not affected".
  defp unknown_sentence(affected) do
    case affected |> entries("unknown") |> clauses(:prose) do
      [] ->
        nil

      clauses ->
        "Whether " <> Enum.join(clauses, "; ") <> separator(clauses) <> "is affected is unknown."
    end
  end

  # The OTP form puts a "corresponding to …" clause between the subject and the
  # verb, which needs a comma to close it; a bare "plug before 1.2.0" does not.
  defp separator(clauses) do
    if Enum.any?(clauses, &String.contains?(&1, "corresponding to")), do: ", ", else: " "
  end

  ## ---------------------------------------------------------------- entries

  # One {name, ranges} per product that has something to say, in record order.
  defp entries(affected, status) do
    described =
      for entry <- affected,
          ranges = status_ranges(entry, status) ++ default_spans(entry, status),
          ranges != [],
          do: %{name: product_name(entry), purl: entry["packageURL"], ranges: ranges}

    described
    |> drop_restatements(&commit_ranges?(&1.ranges))
    |> drop_restatements(&oci_entry?/1)
  end

  # A commit range or an image tag restates a version range we already read
  # aloud — and an OCI entry repeats it once per tag flavor. Both only survive
  # when they are all there is to say.
  defp drop_restatements(described, restatement?) do
    if Enum.any?(described, &(not restatement?.(&1))) do
      Enum.reject(described, restatement?)
    else
      described
    end
  end

  defp commit_ranges?(ranges), do: Enum.all?(ranges, &(&1.type == "git"))

  defp oci_entry?(%{purl: purl}) when is_binary(purl) do
    match?(%Purl{type: "oci"}, Purl.new!(purl))
  end

  defp oci_entry?(_entry), do: false

  # Rows of one status, and only ones with a bound to name.
  defp status_ranges(entry, status) do
    for version <- List.wrap(entry["versions"]),
        version["status"] == status,
        range = range(version),
        range != nil,
        do: range
  end

  # An entry whose `defaultStatus` is `unknown` leaves the span below its lowest
  # affected range unlisted, and the sentence still owes the reader that claim.
  defp default_spans(%{"defaultStatus" => "unknown"} = entry, "unknown") do
    entry["versions"]
    |> List.wrap()
    |> Enum.find(fn version ->
      version["status"] == "affected" and presence(version["version"]) not in [nil, "0"]
    end)
    |> case do
      nil -> []
      version -> [%{lower: nil, uppers: [version["version"]], type: version["versionType"]}]
    end
  end

  defp default_spans(_entry, _status), do: []

  defp range(version) do
    lower = presence(version["version"])
    upper = version["lessThan"] |> presence() |> reject_star()
    inclusive = version["lessThanOrEqual"] |> presence() |> reject_star()
    uppers = List.wrap(upper || inclusive) ++ fix_transitions(version)

    if lower == nil and uppers == [] do
      nil
    else
      %{lower: zero_to_nil(lower), uppers: uppers, type: version["versionType"]}
    end
  end

  # An open range carrying `changes[]` states its fixes as transitions rather
  # than as an upper bound, one per release line — the shape a partially ordered
  # scheme needs, since no single bound can span two lines that never meet.
  # Every one of them ends an affected span, so the sentence names them all;
  # reading only `lessThan` would say "onward" of a fixed vulnerability.
  defp fix_transitions(%{"lessThan" => "*"} = version) do
    for change <- List.wrap(version["changes"]),
        change["status"] == "unaffected",
        at = presence(change["at"]),
        do: at
  end

  defp fix_transitions(_version), do: []

  defp zero_to_nil("0"), do: nil
  defp zero_to_nil(lower), do: lower

  defp reject_star("*"), do: nil
  defp reject_star(value), do: value

  defp presence(nil), do: nil
  defp presence(""), do: nil
  defp presence(value) when is_binary(value), do: value

  ## ---------------------------------------------------------------- clauses

  # Erlang/OTP reads as one clause naming the release and the application; every
  # other product gets a clause of its own.
  defp clauses(entries, style \\ :list) do
    {otp, rest} = Enum.split_with(entries, &otp_entry?/1)

    case otp_clause(otp, style) do
      nil -> Enum.map(rest, &clause(&1, style))
      clause -> [clause | Enum.map(rest, &clause(&1, style))]
    end
  end

  # The "affects" sentence lists products, so a colon separates each from its
  # versions. A clause embedded in prose ("Whether plug before 1.2.0 is
  # affected…") cannot take one.
  defp clause(entry, :list) do
    "#{entry.name}: #{ranges_phrase(entry.ranges)}"
  end

  defp clause(entry, :prose) do
    "#{entry.name} #{ranges_phrase(entry.ranges)}"
  end

  ## -------------------------------------------------------------------- otp

  defp otp_entry?(%{purl: purl}) when is_binary(purl) do
    String.starts_with?(purl, "pkg:sid/erlang.org/otp") or String.starts_with?(purl, "pkg:otp/")
  end

  defp otp_entry?(_entry), do: false

  # "OTP from OTP 17.0 before OTP 28.0.3, corresponding to ssh from 3.0.1
  # before 5.3.3" — release versions carry the `OTP ` prefix a reader expects to
  # see next to them; the application's own versions do not.
  defp otp_clause([], _style), do: nil

  defp otp_clause(entries, style) do
    {release, apps} = Enum.split_with(entries, &(&1.purl =~ "pkg:sid/erlang.org/otp"))

    case {release, apps} do
      {[], apps} ->
        Enum.map_join(apps, "; ", &clause(&1, style))

      {[release | _], []} ->
        "OTP " <> ranges_phrase(release.ranges, &otp_release_version/1)

      {[release | _], apps} ->
        "OTP " <>
          ranges_phrase(release.ranges, &otp_release_version/1) <>
          ", corresponding to " <>
          Enum.map_join(apps, ", and ", &otp_app_phrase(&1))
    end
  end

  defp otp_app_phrase(entry) do
    "#{entry.name} #{ranges_phrase(entry.ranges)}"
  end

  defp otp_release_version(version), do: "OTP " <> version

  ## ------------------------------------------------------------------ ranges

  # Several ranges read as a list; one reads as itself.
  defp ranges_phrase(ranges, decorate \\ & &1) do
    ranges
    |> Enum.map(&range_phrase(&1, decorate))
    |> join_list()
  end

  defp range_phrase(%{lower: nil, uppers: []}, _decorate), do: "all versions"

  defp range_phrase(%{lower: lower, uppers: []}, decorate), do: "from #{version(lower, decorate)} onward"

  defp range_phrase(%{lower: nil, uppers: uppers}, decorate), do: "before #{bounds(uppers, decorate)}"

  defp range_phrase(%{lower: lower, uppers: uppers}, decorate) do
    "from #{version(lower, decorate)} before #{bounds(uppers, decorate)}"
  end

  defp bounds(uppers, decorate) do
    uppers |> Enum.map(&version(&1, decorate)) |> join_list()
  end

  # "a", "a and b", "a, b, and c" — the serial comma keeps a three-version list
  # from reading as two.
  defp join_list([one]), do: one
  defp join_list([a, b]), do: "#{a} and #{b}"

  defp join_list(many) do
    {front, [last]} = Enum.split(many, -1)
    Enum.join(front, ", ") <> ", and " <> last
  end

  # One rendered version: decorated first, then encoded as a whole. "OTP 29.0.2"
  # is one token to a reader, so the prefix's own space binds too — encoding
  # before decorating would leave it breakable.
  defp version(raw, decorate) do
    raw |> decorate.() |> String.replace(~r/\s/, "\u00A0")
  end

  # A version containing whitespace would otherwise wrap mid-version. The
  # escape keeps the codepoint visible in source rather than an invisible byte.

  ## -------------------------------------------------------------- product

  # What the sentence calls the product: its published package name, falling
  # back to the product/vendor fields a nameless entry carries.
  defp product_name(entry) do
    presence(entry["packageName"]) || presence(entry["product"]) || presence(entry["vendor"]) ||
      "the product"
  end
end
