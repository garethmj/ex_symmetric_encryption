# ExSymmetricEncryption
At present only really a worked example of how to decode and decrypt strings that were encrypted by RocketJob's excellent Ruby [SymmetricEncryption](https://github.com/rocketjob/symmetric-encryption) - the result of a couple of hours digging about in the Ruby code and hacking together some Elixir

It is, however, my intent to develop this into a more useable library in order to help me with a gentle migration away from a Rails application that uses SymmetricEncryption extensively so watch this space, I guess.

## Usage
At the moment all you can really do is:

Get your private key from Ruby land:

```ruby
  irb> load './lib/symmetric_encryption.rb'
  irb> SymmetricEncryption.load!("/path/to/your/symmetric-encryption.yml", "production")
  irb> SymmetricEncryption.cipher.send(:key).each_byte.to_a.join(', ')
  "=someGarbledM3ss"
```

Grab the output of that last command and then:

```elixir
  iex> secret = <<2, 5, 7, 9, ...>> # the result of the last Ruby command above.
  iex> ExSymmetricEncryption.decrypt(secret, "a_string_from_your_ruby_land_symmetric_encryption")
  {:ok, "The decrypted string"}
```

Oh, it also only works if your original ciper was `:aes-256-cbc`.

## Installation

If [available in Hex](https://hex.pm/docs/publish), the package can be installed
by adding `ex_symmetric_encryption` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:ex_symmetric_encryption, "~> 0.1.0"}
  ]
end
```

(It is *NOT* currently published on Hex, BTW)