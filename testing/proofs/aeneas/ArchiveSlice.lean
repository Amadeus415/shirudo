-- SPDX-License-Identifier: BSD-2-Clause
-- Copyright (c) 2026 Authors of shirudo

import ArchivePath.FunsExternal
import Contracts

open Aeneas Aeneas.Std Result

namespace Shirudo.AeneasPilot.Archive

def componentBad (s : Slice U8) : Result Bool := do
  let i2 := Slice.len s
  if i2 = 0#usize then ok true
  else
    let i3 := Slice.len s
    if i3 = 1#usize then
      let i4 ← Slice.index_usize s 0#usize
      match i4 with
      | 46#uscalar => ok true
      | _ => ok false
    else
      let i4 := Slice.len s
      if i4 = 2#usize then
        let i5 ← Slice.index_usize s 0#usize
        match i5 with
        | 46#uscalar =>
          let i6 ← Slice.index_usize s 1#usize
          match i6 with
          | 46#uscalar => ok true
          | _ => ok false
        | _ => ok false
      else ok false

theorem componentBad_eq (s : Slice U8) :
    componentBad s = ok (ArchivePath.bad (s.val.map UScalar.val)) := by
  have hdot : (46#uscalar : U8).val = 46 := rfl
  generalize hx : s.val = xs
  cases xs with
  | nil => simp [componentBad, Slice.len, ArchivePath.bad, hx]
  | cons a xs =>
    cases xs with
    | nil =>
      simp [componentBad, Slice.len, Slice.index_usize,
        ArchivePath.bad, ArchivePath.dot, hx, UScalar.eq_equiv]
      split <;> simp_all [UScalar.eq_equiv]
    | cons b xs =>
      cases xs with
      | nil =>
        simp [componentBad, Slice.len, Slice.index_usize,
          ArchivePath.bad, ArchivePath.dot, hx, UScalar.eq_equiv]
        split <;> (try split) <;> simp_all [UScalar.eq_equiv]
      | cons c xs =>
        simp [componentBad, Slice.len, ArchivePath.bad, hx]

theorem slice_eq (a b : Slice U8) :
    core.slice.cmp.PartialEqSlice.eq core.cmp.PartialEqU8 a b =
      ok (decide (a.val = b.val)) := by
  have h := core.slice.cmp.PartialEqSlice.eq_homo_spec core.cmp.PartialEqU8 a b
    (by intro x y; simp [liftFun2])
  have hs : core.slice.cmp.PartialEqSlice.eq core.cmp.PartialEqU8 a b
      ⦃ r => r = decide (a.val = b.val) ⦄ := by
    apply WP.spec_mono h
    intro r hr
    cases r <;> by_cases he : a.val = b.val <;> simp [Slice.eq_iff, he] at hr ⊢
  generalize hh : core.slice.cmp.PartialEqSlice.eq core.cmp.PartialEqU8 a b = result at hs ⊢
  cases result with
  | ret r => exact congrArg Result.ok ((WP.spec_ok r).mp hs)
  | div => simp at hs
  | vis e k => simp at hs

theorem starts_with_eq (a b : Slice U8) :
    core.slice.Slice.starts_with core.cmp.PartialEqU8 a b =
      ok (decide (a.val.take b.val.length = b.val)) := by
  unfold core.slice.Slice.starts_with
  split
  · rw [slice_eq]
    simp
  · rename_i hlong
    have hne : a.val.take b.val.length ≠ b.val := by
      intro he
      have hlen := congrArg List.length he
      simp only [List.length_take] at hlen
      agrind
    simp [hne]

end Shirudo.AeneasPilot.Archive
