defmodule Salchicha.MixProject do
  use Mix.Project

  if String.to_integer(System.otp_release()) < 22 do
    IO.warn("Salchicha requires OTP 22 or higher. Some function calls may fail.")
  end

  def project do
    [
      app: :salchicha,
      version: "0.3.0",
      elixir: "~> 1.12",
      name: "Salchicha",
      source_url: "https://github.com/BrandtHill/Salchicha",
      start_permanent: Mix.env() == :prod,
      description: description(),
      package: package(),
      deps: deps(),
      docs: docs()
    ]
  end

  def application do
    []
  end

  defp description do
    "An Elixir NaCl/libsodium-lite Salsa20/ChaCha20 encryption tool"
  end

  # Run "mix help deps" to learn about dependencies.
  def deps do
    [
      {:ex_doc, "~> 0.37", only: :dev, runtime: false}
    ]
  end

  def docs do
    [
      main: "Salchicha",
      source_ref: "master"
    ]
  end

  defp package do
    [
      name: :salchicha,
      maintainers: "Brandt Hill",
      licenses: ["MIT"],
      files: [
        "lib",
        "README*",
        "LICENSE*",
        "mix.exs"
      ],
      links: %{
        "GitHub" => "https://github.com/BrandtHill/Salchicha"
      }
    ]
  end
end
