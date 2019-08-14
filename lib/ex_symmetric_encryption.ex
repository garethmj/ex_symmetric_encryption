defmodule ExSymmetricEncryption do
  @moduledoc """
  Documentation for ExSymmetricEncryption.
  """

  @doc """
  Decode a string encrypted with RocketJob's Ruby [SymmetricEncryption](https://github.com/rocketjob/symmetric-encryption)
  module.

  ## Examples
      iex> ExSymmetricEncryption.decode("QEVuQwJAEACxHQ49ppIkBYvmzylpFNiO9BC7+43wJTxpjqxRa3NQtg==")

      iex> secret = "BLAH"
      iex> ExSymmetricEncryption.decrypt(secret, "QEVuQwJAEACxHQ49ppIkBYvmzylpFNiO9BC7+43wJTxpjqxRa3NQtg==")
  """
  def decode(cipher_text) do
    {:ok, decoded} =
      cipher_text
      |> :base64.decode()
      |> check_magic_header()

    decoded
    |> unpack_header()
    |> IO.inspect()
  end

  def decrypt(key, cipher_text) do
    check_header = cipher_text |> :base64.decode() |> check_magic_header()

    case check_header do
      {:ok, text} ->
        {header, decoded_cipher} = unpack_header(text)
        ExCrypto.decrypt(key, header.iv, decoded_cipher)

      {:no_header, _cipher_text} ->
        {:error, "Encrypted strings with no magic header are not yet supported."}
    end
  end

  def unpack_header(decoded) do
    decoded
    |> extract_flags()
    |> maybe_extract_iv()
    |> maybe_extract_key()
    |> maybe_extract_cipher_name()
  end

  defp check_magic_header(decoded) do
    <<magic_header::bytes-size(4), rest::binary>> = decoded

    case magic_header do
      "@EnC" -> {:ok, rest}
      _ -> {:no_header, decoded}
    end
  end

  defp extract_flags(decoded) do
    <<cipher_ver::integer(), flags::bytes-size(1), rest::binary>> = decoded
    <<compressed::1, iv::1, key::1, cipher_name::1, auth_tag::1, _reserved::3>> = flags

    header_with_flags = %{
      flag_cipher_version: cipher_ver,
      flag_compressed: truthise(compressed),
      flag_iv: truthise(iv),
      flag_key: truthise(key),
      flag_cipher_name: truthise(cipher_name),
      flag_auth_tag: truthise(auth_tag),
      # other header components for later use
      iv: nil,
      key: nil,
      cipher_name: nil
    }

    {header_with_flags, rest}
  end

  defp maybe_extract_iv({%{flag_iv: has_iv} = header, decoded}) do
    case has_iv do
      true ->
        {iv, rest} = extract_header_item_by_length(decoded)
        {%{header | iv: iv}, rest}

      false ->
        {header, decoded}
    end
  end

  defp maybe_extract_key({%{flag_key: has_key} = header, decoded}) do
    case has_key do
      true ->
        {key, rest} = extract_header_item_by_length(decoded)
        {%{header | key: key}, rest}

      false ->
        {header, decoded}
    end
  end

  defp maybe_extract_cipher_name({%{flag_cipher_name: has_cipher_name} = header, decoded}) do
    case has_cipher_name do
      true ->
        {cipher_name, rest} = extract_header_item_by_length(decoded)
        {%{header | cipher_name: cipher_name}, rest}

      false ->
        {header, decoded}
    end
  end

  # Wait, what the jeggins is going on here then?
  # Well. Glad you asked. Basically the Ruby code unpacks byte slices of the
  # header using this tidbit:
  #   ```ruby
  #     len    = buffer.byteslice(offset, 2).unpack('v').first
  #     offset += 2
  #     out    = buffer.byteslice(offset, len)
  #   ```
  #
  # See [the String doco](https://apidock.com/ruby/String/unpack) for more info.
  #
  # In elixir that just means poping a 16 bit little endian int off the binary
  # using the relevant bitstring specifier in a pattern match, hence:
  #
  #  ```elixir
  #    <<item_length::16-unsigned-little-integer, rest::binary>>
  #  ```
  #
  # After that we just use the retrived lenght in the next pattern match to
  # get the header item itself (so IV, key or cipher name).
  defp extract_header_item_by_length(decoded) do
    <<item_length::16-unsigned-little-integer, rest::binary>> = decoded
    <<item::bytes-size(item_length), rest::binary>> = rest

    {item, rest}
  end

  defp truthise(bit) when is_integer(bit) do
    if bit == 1, do: true, else: false
  end
end
