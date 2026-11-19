-- SPDX-License-Identifier: BSD-2-Clause
-- Copyright (c) 2026 Authors of shirudo

import Aeneas
import Contracts

open Aeneas Aeneas.Std

namespace Shirudo.AeneasPilot.Archive

theorem take_takeWhile {α : Type} (p : α → Bool) (xs : List α) :
    xs.take (xs.takeWhile p).length = xs.takeWhile p := by
  have h := congrArg (List.take (xs.takeWhile p).length)
    (List.takeWhile_append_dropWhile (p := p) (l := xs))
  simpa only [List.take_left] using h.symm

theorem drop_takeWhile {α : Type} (p : α → Bool) (xs : List α) :
    xs.drop (xs.takeWhile p).length = xs.dropWhile p := by
  have h := congrArg (List.drop (xs.takeWhile p).length)
    (List.takeWhile_append_dropWhile (p := p) (l := xs))
  simpa only [List.drop_left] using h.symm

theorem drop_clamp {α : Type} (xs : List α) (n : Nat) :
    xs.drop (min n xs.length) = xs.drop n := by
  by_cases h : n ≤ xs.length
  · simp [Nat.min_eq_left h]
  · have hn : xs.length ≤ n := Nat.le_of_lt (Nat.lt_of_not_ge h)
    simp [Nat.min_eq_right hn, List.drop_eq_nil_iff.mpr hn]

theorem relLoop_step (xs : List Nat) :
    ArchivePath.relLoop xs =
      if xs = [] then true
      else if ArchivePath.bad (xs.take (xs.takeWhile ArchivePath.notSlash).length) then false
      else ArchivePath.relLoop
        (xs.drop (min ((xs.takeWhile ArchivePath.notSlash).length + 1) xs.length)) := by
  rw [take_takeWhile, drop_clamp]
  have hd : xs.drop ((xs.takeWhile ArchivePath.notSlash).length + 1) =
      (xs.dropWhile ArchivePath.notSlash).drop 1 := by
    rw [← List.drop_drop, drop_takeWhile]
  rw [hd, ArchivePath.relLoop.eq_def]
  split
  · rfl
  · split
    · rfl
    · cases hs : xs.dropWhile ArchivePath.notSlash
      · simp [ArchivePath.relLoop]
      · rfl

theorem position_length {α : Type} (p : α → Bool) (xs : List α) :
    (xs.findIdx? p).getD xs.length =
      (xs.takeWhile (fun x => !(p x))).length := by
  induction xs
  · simp
  · rename_i x xs ih
    cases hx : p x
    · cases ht : xs.findIdx? p <;>
        simp [List.findIdx?_cons, hx, ht] at ih ⊢ <;> exact ih
    · simp [List.findIdx?_cons, hx]

theorem takeWhile_values (xs : List U8) :
    (xs.map UScalar.val).takeWhile ArchivePath.notSlash =
      (xs.takeWhile (fun x => !(decide (x = 47#u8)))).map UScalar.val := by
  rw [List.takeWhile_map]
  fcongr 2
  funext x
  change (x.val != ArchivePath.slash) = !(decide (x = 47#u8))
  by_cases hx : x.val = 47
  · simp [ArchivePath.slash, UScalar.eq_equiv, hx]
  · simp [ArchivePath.slash, hx]

theorem memberNameOk_step (path member : List Nat) :
    let n := (path.takeWhile ArchivePath.notSlash).length
    ArchivePath.memberNameOk path member =
      (ArchivePath.relOk path &&
        (if n < path.length then
          decide (n ≠ 0) && decide (path.take 2 ≠ [ArchivePath.dot, ArchivePath.slash]) &&
            ArchivePath.relOk member && decide (path.drop (n + 1) = member)
        else false)) := by
  dsimp only
  unfold ArchivePath.memberNameOk
  by_cases h : (path.takeWhile ArchivePath.notSlash).length < path.length
  · simp [h, List.length_eq_zero_iff, Bool.and_assoc]
  · simp [h]

end Shirudo.AeneasPilot.Archive
