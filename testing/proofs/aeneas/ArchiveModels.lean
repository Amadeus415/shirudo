-- SPDX-License-Identifier: BSD-2-Clause
-- Copyright (c) 2026 Authors of shirudo

module
public import Aeneas

@[expose] public section

open Aeneas Aeneas.Std Result

def core.option.Option.is_none_or
    {T F : Type _} (inst : core.ops.function.FnOnce F T Bool)
    (value : Option T) (f : F) : Result Bool :=
  match value with
  | none => ok true
  | some x => inst.call_once f x

def core.slice.Slice.first {T : Type _} (s : Slice T) : Result (Option T) :=
  ok s.val.head?

def core.slice.Slice.starts_with
    {T : Type _} (inst : core.cmp.PartialEq T T)
    (s needle : Slice T) : Result Bool := do
  if needle.val.length ≤ s.val.length then
    let head := Slice.from (s.val.take needle.val.length) (by scalar_tac)
    core.slice.cmp.PartialEqSlice.eq inst head needle
  else ok false
