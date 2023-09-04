defmodule Gollum.Host do
  @moduledoc """
  Represents one host's robots.txt files.
  """

  # Its just a small wrapper.
  @type t :: %Gollum.Host{host: binary, rules: map}
  @enforce_keys [:host, :rules]
  defstruct host: "", rules: %{}

  @doc """
  Creates a new `Gollum.Host` struct, passing in the host and rules.
  The rules usually are the output of the parser.

  ## Examples
  ```
  iex> alias Gollum.Host
  iex> rules = %{"Hello" => %{allowed: [], disallowed: []}}
  iex> Host.new("hello.net", rules)
  %Gollum.Host{host: "hello.net", rules: %{"Hello" => %{allowed: [], disallowed: []}}}
  ```
  """
  @spec new(binary, map) :: Gollum.Host.t
  def new(host, rules) do
    %Gollum.Host{host: host, rules: rules}
  end

  @doc """
  Returns whether a specified path is crawlable by the specified user agent,
  based on the rules defined in the specified host struct.

  Checks are done based on the specification defined by Google, which can be
  found [here](https://developers.google.com/search/reference/robots_txt).

  ## Examples
  ```
  iex> alias Gollum.Host
  iex> rules = %{
  ...>   "hello" => %{
  ...>     allowed: ["/p"],
  ...>     disallowed: ["/"],
  ...>   },
  ...>   "otherhello" => %{
  ...>     allowed: ["/$"],
  ...>     disallowed: ["/"],
  ...>   },
  ...>   "*" => %{
  ...>     allowed: ["/page"],
  ...>     disallowed: ["/*.htm"],
  ...>   },
  ...> }
  iex> host = Host.new("hello.net", rules)
  iex> Host.crawlable?(host, "Hello", "/page")
  :crawlable
  iex> Host.crawlable?(host, "OtherHello", "/page.htm")
  :uncrawlable
  iex> Host.crawlable?(host, "NotHello", "/page.htm")
  :undefined
  ```
  """
  @spec crawlable?(Gollum.Host.t, binary, binary) :: :crawlable | :uncrawlable | :undefined
  def crawlable?(%Gollum.Host{rules: rules}, _user_agent, _path) when rules == %{} do
    # Empty robots.txt: no rules and everything allowed.
    :crawlable
  end
  def crawlable?(%Gollum.Host{}, "", _path) do
    # Empty user-agent to be matched: everything allowed.
    :crawlable
  end
  def crawlable?(%Gollum.Host{}, _user_agent, "") do
    #  Empty url: implicitly disallowed.
    :uncrawlable
  end
  def crawlable?(%Gollum.Host{rules: rules}, user_agent, path) do
    case contains_unicode?(path) do
      false ->
        case valid_user_agent?(user_agent) do
          true ->
            do_crawlable(merge_rules_map(rules), user_agent, path)
          false ->
            :uncrawlable
        end
      true ->
        # Path must be valid ASCII string, any other characters must be
        # percent-encoded (https://www.rfc-editor.org/rfc/rfc9309.html#section-2.2.2)
        :uncrawlable
    end
  end

  defp contains_unicode?(string) when is_binary(string) do
    String.to_charlist(string)
    |> Enum.any?(fn codepoint -> codepoint > 127 end)
  end

  @spec do_crawlable(map, binary, binary) :: :crawlable | :uncrawlable | :undefined
  defp do_crawlable(rules, user_agent, path) do
    # Determine the user agent
    key =
      rules
      |> Map.keys()
      |> which_agent(user_agent)

    # Return whether allowed
    if key do
      rules
      |> Map.get(key)
      |> sanitize_user_agent_map()
      |> allowed?(path)
      |> case do
        :allowed -> :crawlable
        :disallowed -> :uncrawlable
        :undefined -> :undefined
      end
    else
      # Return crawlable if user-agent not found
      :crawlable
    end
  end

  @doc false
  # Accept user-agent value up to the first space. Space is not
  # allowed in user-agent values, but that doesn't stop webmasters from using
  # them. This is more restrictive than the RFC, since in case of the bad value
  # "Googlebot Images" we'd still obey the rules with "Googlebot".
  # Extends REP RFC section "The user-agent line"
  # https://www.rfc-editor.org/rfc/rfc9309.html#section-2.2.1
  defp valid_user_agent?(user_agent) do
    user_agent
    |> String.downcase()
    |> String.trim()
    |> String.split()
    |> case do
      [_agent] -> true
      _ -> false
    end
  end

  defp merge_rules_map(nil), do: %{}
  defp merge_rules_map(rules) do
    Enum.reduce(rules, %{}, fn {agent, rule_map}, acc ->
      # We want to do case insensitive matching on the user agent
      downcased_agent = String.downcase(agent)

      merged_rule_map =
        case acc[downcased_agent] do
          nil ->
            # No duplicate found, just add the rules
            rule_map
          existing_value ->
            # Duplicate found, merge the rules
            %{
              allowed: rule_map[:allowed] ++ existing_value[:allowed] |> Enum.uniq(),
              disallowed: rule_map[:disallowed] ++ existing_value[:disallowed] |> Enum.uniq()
            }
        end

      Map.put(acc, downcased_agent, merged_rule_map)
    end)
  end

  defp sanitize_user_agent_map(nil), do: %{allowed: [], disallowed: []}
  defp sanitize_user_agent_map(%{allowed: _, disallowed: _} = map), do: map
  defp sanitize_user_agent_map(%{allowed: allowed}), do: %{allowed: allowed, disallowed: []}
  defp sanitize_user_agent_map(%{disallowed: disallowed}), do: %{allowed: [], disallowed: disallowed}

  @doc false
  # Returns the most suitable user agent string from the specified list, based
  # on the specified user agent string. If none are found, returns nil. Checks
  # are case insensitive.
  def which_agent(agents, agent) when is_binary(agent) do
    agent = String.downcase(agent)
    agents
    |> Enum.map(&String.downcase/1)
    |> Enum.filter(&match_agent?(&1, agent))
    |> Enum.max_by(&String.length/1, fn -> nil end)
  end

  @doc false
  # Returns whether the user agent string on the left matches the user agent
  # string on the right.
  def match_agent?(lhs, rhs) do
    String.starts_with?(lhs, rhs) || lhs == "*"
  end

  defp maybe_decode(rule) do
    case contains_unicode?(rule) do
      false -> rule
      true -> URI.encode(rule)
    end
  end

  @doc false
  # Returns whether a path is allowed to be accessed.
  # Return value is :allowed, :disallowed or :undefined
  def allowed?(%{allowed: allowed, disallowed: disallowed}, path) do
    reduce_by_match_length = fn rule, acc ->
      case match_path?(path, maybe_decode(rule)) do
        {true, match_length} -> [{rule, match_length} | acc]
        false -> acc
      end
    end

    #allowed = Enum.filter(allowed, &match_path?(path, &1))
    allowed = Enum.reduce(allowed, [], reduce_by_match_length)
    #disallowed = Enum.filter(disallowed, &match_path?(path, &1))
    disallowed = Enum.reduce(disallowed, [], reduce_by_match_length)

    # Check for empty array before finding max
    cond do
      length(disallowed) == 0 -> :allowed
      length(allowed)    == 0 -> :disallowed
      true -> do_allowed(allowed, disallowed)
    end
  end

  # Returns :allowed, :disallowed or :undefined based on the most specified
  # rule. Returns undefined if at least 1 of the rules contains a wildcard.
  defp do_allowed(allowed, disallowed) do
    max_by_length = fn {_rule, match_length} -> match_length end

    max_allowed = Enum.max_by(allowed, max_by_length)
    max_disallowed = Enum.max_by(disallowed, max_by_length)

    {max_allowed_rule, max_allowed_match_length} = max_allowed
    {max_disallowed_rule, max_disallowed_match_length} = max_disallowed

    #contains_wildcard = &String.contains?(&1, "*")

    # Check for wildcards
    cond do
      #contains_wildcard.(max_allowed) || contains_wildcard.(max_disallowed) -> :undefined
      max_allowed_rule == max_disallowed_rule                 -> :allowed
      max_allowed_match_length == max_disallowed_match_length -> :undefined
      max_allowed_match_length > max_disallowed_match_length  -> :allowed
      max_allowed_match_length < max_disallowed_match_length  -> :disallowed
    end
  end

  @doc false
  # Returns whether the path on the left matches the path on the right. The
  # path on the right can contain wildcards and other special characters.
  # Assumes valid input.
  def match_path?(lhs, rhs) do
    rhs = String.split(rhs, "*")
    do_match_path(lhs, rhs, 0)
  end

  # Does the actual path matching
  defp do_match_path(_, [], match_len), do: {true, match_len}
  defp do_match_path("", _, _match_len), do: false
  defp do_match_path(lhs, [group | rest], match_len) do
    case do_match_group(lhs, group, match_len) do
      {:ok, remaining, new_match_len} -> do_match_path(remaining, rest, new_match_len)
      :error -> false
    end
  end

  # Matches the left hand side chars to the right hand side chars
  # Recognises the "$" sign. Assumes valid input.
  # e.g. {:ok, "llo"} = do_match_group("hello", "he")
  # e.g. {:ok, "llo"} = do_match_group("yohello", "helloo")
  # e.g. :error = do_match_group("hello", "helloo")
  # e.g. :error = do_match_group("hello", "he$")
  defp do_match_group("", "", match_len), do:
    {:ok, "", match_len}
  defp do_match_group("", "$" <> _rhs, match_len), do:
    {:ok, "", match_len}
  defp do_match_group(_lhs, "$" <> _rhs, _match_len), do:
    :error
  defp do_match_group("", _rhs, _match_len), do:
    :error
  defp do_match_group(lhs, "", match_len), do:
    {:ok, lhs, match_len}
  defp do_match_group(<<ch::utf8, lhs::binary>>, <<ch::utf8, rhs::binary>>, match_len), do:
    do_match_group(lhs, rhs, match_len + 1)
  defp do_match_group(<<_ch::utf8, lhs::binary>>, rhs, match_len), do:
    do_match_group(lhs, rhs, match_len + 1)
end
