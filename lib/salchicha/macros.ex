defmodule Salchicha.Macros do
  @moduledoc false

  @doc """
  This macro generates a function `update_tuple/3` that returns a new 16-element
  with 4 of its values at given indexes updated. This creates a single shallow copy of the
  original tuple as opposed to calling `put_elem/3` 4 times creating 4 copies of the tuple.
  This dramatically reduces memory usage and improves speed.

  Calling `Salchicha.Macros.def_update_tuple 0, 4, 8, 12` defines a function that looks like this:
  ```elixir
  defp update_tuple(
        {_e0, e1, e2, e3, _e4, e5, e6, e7, _e8, e9, e10, e11, _e12, e13, e14, e15},
        {0, 4, 8, 12},
        {a, b, c, d}
      ),
      do: {a, e1, e2, e3, b, e5, e6, e7, c, e9, e10, e11, d, e13, e14, e15}
  ```
  """
  defmacro def_update_tuple(index_a, index_b, index_c, index_d) do
    indexes = [index_a, index_b, index_c, index_d]

    input_tuple_elements =
      for i <- 0..15, do: Macro.var(:"#{(i in indexes && "_") || ""}e#{i}", __MODULE__)

    output_tuple_elements =
      Enum.with_index(input_tuple_elements, fn
        _elem, ^index_a -> quote do: a
        _elem, ^index_b -> quote do: b
        _elem, ^index_c -> quote do: c
        _elem, ^index_d -> quote do: d
        elem, _non_updated -> elem
      end)

    quote do
      defp update_tuple(
             {unquote_splicing(input_tuple_elements)},
             {unquote(index_a), unquote(index_b), unquote(index_c), unquote(index_d)},
             {a, b, c, d}
           ) do
        {unquote_splicing(output_tuple_elements)}
      end
    end
  end
end
