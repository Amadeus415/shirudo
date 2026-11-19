-- SPDX-License-Identifier: BSD-2-Clause
-- Copyright (c) 2026 Authors of shirudo

import ArchivePath.Funs
import Contracts
import ArchiveList
import ArchiveSlice

open Aeneas Aeneas.Std Result
open Aeneas.Std.ControlFlow

namespace Shirudo.AeneasPilot.Archive

def bytes (s : Slice U8) : Bytes := s.val.map (fun x => x.bv.toFin)

def values (s : Slice U8) : List Nat := s.val.map UScalar.val

theorem byte_values (s : Slice U8) : byteValues (bytes s) = values s := by
  simp only [byteValues, bytes, values, List.map_map]
  apply List.map_congr_left
  intro x _
  rfl

@[step]
theorem position_spec {P : Type}
    (inst : core.ops.function.FnMut P U8 Bool) (p : P) (s : Slice U8)
    (g : U8 → Bool)
    (hg : ∀ p x, x ∈ s.val → inst.call_mut p x = ok (g x, p)) :
    core.slice.iter.Iter.Insts.CoreIterTraitsIteratorIteratorSharedAT.position
      inst ⟨s, 0⟩ p
      ⦃ (r : Option Usize) (_ : core.slice.iter.Iter U8) =>
        r.map UScalar.val = s.val.findIdx? g ⦄ := by
  unfold core.slice.iter.Iter.Insts.CoreIterTraitsIteratorIteratorSharedAT.position
  have hy := core.slice.iter.IteratorSliceIter.next.yields s.val.length
    (⟨s, 0⟩ : core.slice.iter.Iter U8) (by simp)
  apply WP.spec_mono
    (core.iter.traits.iterator.Iterator.position.default.loop.spec_yields
      core.slice.iter.IteratorSliceIter.next inst g s.val ⟨s, 0⟩ p
      ⟨s, s.val.length⟩ (by simpa using hy) hg s.property)
  intro r hr
  exact hr.1

@[step]
theorem slash_position_spec (s : Slice U8) :
    core.slice.iter.Iter.Insts.CoreIterTraitsIteratorIteratorSharedAT.position
      archive_path.subject.archive_rel_ok.closure_1.Insts.CoreOpsFunctionFnMutTupleShared0U8Bool
      ⟨s, 0⟩ ()
      ⦃ (r : Option Usize) (_ : core.slice.iter.Iter U8) =>
        r.map UScalar.val = s.val.findIdx? (fun x => decide (x = 47#u8)) ⦄ := by
  apply position_spec
  intro p x _
  cases p
  rfl

theorem body_spec (harch : System.Platform.numBits = 64)
    (rest : Slice U8) (hbound : rest.length ≤ 2^63 - 1) :
    archive_path.subject.archive_rel_ok_loop.body rest
      ⦃ (r : ControlFlow (Slice U8) Bool) =>
        match r with
        | .done b => b = ArchivePath.relLoop (values rest)
        | .cont next => next.length < rest.length ∧ next.length ≤ 2^63 - 1 ∧
            ArchivePath.relLoop (values next) = ArchivePath.relLoop (values rest) ⦄ := by
  unfold archive_path.subject.archive_rel_ok_loop.body
  simp only [core.slice.Slice.is_empty]
  by_cases hz : rest.length = 0
  · have he : rest.val = [] := List.length_eq_zero_iff.mp hz
    rw [ArchivePath.relLoop.eq_def]
    simp [values, he]
  · simp only [hz, decide_false, core.slice.Slice.iter, bind_ok,
      Bool.false_eq_true, ite_false]
    apply WP.spec_bind (slash_position_spec rest)
    rintro ⟨o, it⟩ ho
    generalize hn : core.option.Option.unwrap_or o (Slice.len rest) = n
    have hnval : n.val = ((values rest).takeWhile ArchivePath.notSlash).length := by
      rw [← hn]
      have hm : (core.option.Option.unwrap_or o (Slice.len rest)).val =
          (rest.val.findIdx? (fun x => decide (x = 47#u8))).getD rest.length := by
        rw [← ho]
        cases o <;> rfl
      rw [hm, position_length]
      simp only [values, takeWhile_values, List.length_map]
    have hnle : n.val ≤ rest.length := by
      rw [hnval]
      have h := List.takeWhile_sublist (p := ArchivePath.notSlash) (l := values rest)
      simpa only [values, List.length_map] using h.length_le
    simp only [lift, bind_ok]
    step as ⟨s, hs, hslen⟩
    rw [hn] at hs hslen ⊢
    change (do
      let b ← componentBad s
      if b then ok (done false : ControlFlow (Slice U8) Bool)
      else
        let next ← n + 1#usize
        let tail ← core.slice.index.SliceIndexRangeFromUsizeSlice.index
          { start := core.cmp.impls.OrdUsize.min next (Slice.len rest) } rest
        ok (cont tail : ControlFlow (Slice U8) Bool)) ⦃ _ ⦄
    rw [componentBad_eq]
    simp only [bind_ok]
    have hsvalues : values s = (values rest).take n.val := by
      simp only [values, hs, List.slice, List.drop_zero, Nat.sub_zero, List.map_take]
    have hmodel := relLoop_step (values rest)
    have hnonempty : values rest ≠ [] := by
      simpa [values, List.length_eq_zero_iff] using hz
    rw [ite_eq_right hnonempty, ← hnval, ← hsvalues] at hmodel
    split
    · rename_i hbad
      change ArchivePath.bad (values s) = true at hbad
      simp only [WP.spec_ok]
      rw [hbad] at hmodel
      exact hmodel.symm
    · rename_i hbad
      change ¬ ArchivePath.bad (values s) = true at hbad
      have hadd : n.val + (1#usize).val ≤ Usize.max := by
        have hmax : Usize.max = 2^64 - 1 := by
          simp [Usize.max, Usize.numBits, harch]
        have hone : (1#usize).val = 1 := by simp
        rw [hmax, hone]
        exact Nat.le_trans (Nat.add_le_add_right (Nat.le_trans hnle hbound) 1) (by decide)
      step as ⟨next, hnext⟩
      step as ⟨tail, htail, htaillen⟩
      have hmin : (core.cmp.impls.OrdUsize.min next (Slice.len rest)).val =
          min (n.val + 1) rest.length := by
        simp only [core.cmp.impls.OrdUsize.min_val, Slice.len_val, hnext]
      rw [hmin] at htail htaillen
      refine ⟨?_, ?_, ?_⟩
      · rw [htaillen]
        agrind
      · rw [htaillen]
        exact Nat.le_trans (Nat.sub_le _ _) hbound
      · rw [ite_eq_right hbad] at hmodel
        rw [hmodel]
        fcongr 1
        simp only [values, htail, List.map_drop, List.length_map]

@[step]
theorem loop_spec (harch : System.Platform.numBits = 64)
    (rest : Slice U8) (hbound : rest.length ≤ 2^63 - 1) :
    archive_path.subject.archive_rel_ok_loop rest
      ⦃ (b : Bool) => b = ArchivePath.relLoop (values rest) ⦄ := by
  unfold archive_path.subject.archive_rel_ok_loop
  apply loop.spec_decr_nat (measure := fun s : Slice U8 => s.length)
    (inv := fun s => s.length ≤ 2^63 - 1 ∧
      ArchivePath.relLoop (values s) = ArchivePath.relLoop (values rest))
  · intro s hs
    apply WP.spec_mono (body_spec harch s hs.1)
    intro r hr
    cases r
    · exact ⟨⟨hr.2.1, hr.2.2.trans hs.2⟩, hr.1⟩
    · exact hr.trans hs.2
  · exact ⟨hbound, rfl⟩

theorem archive_rel_eq (harch : System.Platform.numBits = 64)
    (path : Slice U8) (hbound : path.length ≤ 2^63 - 1) :
    archive_path.subject.archive_rel_ok path = ok (ArchivePath.relOk (values path)) := by
  obtain ⟨b, hb, he⟩ := WP.spec_exists_ok (loop_spec harch path hbound)
  unfold archive_path.subject.archive_rel_ok
  simp only [core.slice.Slice.first, bind_ok]
  cases hp : path.val
  · simp [hp, core.option.Option.is_none_or, values, ArchivePath.relOk]
  · rename_i c cs
    simp only [List.head?_cons, core.option.Option.is_none_or,
      archive_path.subject.archive_rel_ok.closure.Insts.CoreOpsFunctionFnOnceTupleShared0U8Bool.call_once,
      bind_ok]
    by_cases hc : c = 47#u8
    · simp [hc, values, hp, ArchivePath.relOk, ArchivePath.slash]
    · have hcval : c.val ≠ ArchivePath.slash := by
        simpa [UScalar.eq_equiv, ArchivePath.slash] using hc
      simp [hc, hb, he, values, hp, ArchivePath.relOk, hcval]

def runArchiveRel (path : Slice U8) : Option Bool :=
  match (archive_path.subject.archive_rel_ok path).match with
  | .ok b => some b
  | _ => none

/-- The extracted target uses 64-bit pointer widths. -/
theorem archive_rel_contract (harch : System.Platform.numBits = 64) :
    ArchiveRelRefines bytes runArchiveRel := by
  intro path hbound
  have hs : path.length ≤ 2^63 - 1 := by simpa [bytes] using hbound
  simp [runArchiveRel, archive_rel_eq harch path hs, byte_values]

theorem value_map_eq (xs ys : List U8) :
    xs.map UScalar.val = ys.map UScalar.val ↔ xs = ys := by
  exact List.map_inj_right (fun _ _ h => UScalar.eq_of_val_eq h)

@[step]
theorem member_position_spec (s : Slice U8) :
    core.slice.iter.Iter.Insts.CoreIterTraitsIteratorIteratorSharedAT.position
      archive_path.subject.package_member_name_ok.closure.Insts.CoreOpsFunctionFnMutTupleShared0U8Bool
      ⟨s, 0⟩ ()
      ⦃ (r : Option Usize) (_ : core.slice.iter.Iter U8) =>
        r.map UScalar.val = s.val.findIdx? (fun x => decide (x = 47#u8)) ⦄ := by
  apply position_spec
  intro p x _
  cases p
  rfl

theorem package_member_eq (harch : System.Platform.numBits = 64)
    (path : Slice U8) (member : Option (Slice U8))
    (hbound : path.length ≤ 2^63 - 1)
    (hmembers : ∀ m, member = some m → m.length ≤ 2^63 - 1) :
    archive_path.subject.package_member_name_ok path member = ok (match member with
      | none => false
      | some m => ArchivePath.memberNameOk (values path) (values m)) := by
  cases member
  · rfl
  · rename_i m
    have hmbound := hmembers m rfl
    unfold archive_path.subject.package_member_name_ok
    rw [archive_rel_eq harch path hbound]
    simp only [bind_ok]
    have hmodel := memberNameOk_step (values path) (values m)
    split
    · rename_i hrel
      simp only [core.slice.Slice.iter, bind_ok]
      obtain ⟨⟨o, it⟩, hp, ho⟩ := WP.spec_exists_ok (member_position_spec path)
      rw [hp, bind_ok]
      have hn : ((values path).takeWhile ArchivePath.notSlash).length =
          (o.map UScalar.val).getD path.length := by
        rw [ho, position_length]
        simp only [values, takeWhile_values, List.length_map]
      cases o
      · simp only [Option.map_none, Option.getD_none] at hn
        rw [hmodel, hn]
        simp [values]
      · rename_i n
        simp only [Option.map_some, Option.getD_some] at hn
        have hlt : n.val < path.length := by
          exact (List.findIdx?_eq_some_iff_getElem.mp ho.symm).1
        rw [hmodel, hn]
        have hlen : (values path).length = path.length := by simp [values]
        rw [hlen]
        simp only [hlt, ite_true, hrel, Bool.true_and]
        have hprefix : path.val.take 2 = [46#u8, 47#u8] ↔
            (values path).take 2 = [ArchivePath.dot, ArchivePath.slash] := by
          rw [values, ← List.map_take]
          change path.val.take 2 = [46#u8, 47#u8] ↔
            (path.val.take 2).map UScalar.val = [46#u8, 47#u8].map UScalar.val
          exact (value_map_eq _ _).symm
        by_cases hnzero : n.val = 0
        · simp [UScalar.eq_equiv, hnzero]
        · have hadd : n.val + (1#usize).val ≤ Usize.max := by
            have hpbound := path.property
            scalar_tac
          obtain ⟨next, hnext, hnval⟩ := WP.spec_exists_ok
            (Usize.add_spec (x := n) (y := 1#usize) hadd)
          have hnextle : next.val ≤ path.length := by agrind
          obtain ⟨tail, htail, htval, _⟩ := WP.spec_exists_ok
            (core.slice.index.SliceIndexRangeFromUsizeSlice.index.step_spec
              { start := next } path hnextle)
          simp [UScalar.eq_equiv, hnzero, lift, Array.to_slice, Array.make,
            starts_with_eq, hprefix, archive_rel_eq harch m hmbound, hnext,
            htail, slice_eq, htval, hnval, values]
          simp only [← List.map_drop, value_map_eq]
          split <;> rename_i hpfx
          · simp [hpfx]
          · cases ArchivePath.relOk (m.val.map UScalar.val) <;> simp [hpfx]
    · rename_i hrel
      rw [hmodel]
      simp [hrel]

def runPackageMember (path : Slice U8) (member : Option (Slice U8)) : Option Bool :=
  match (archive_path.subject.package_member_name_ok path member).match with
  | .ok b => some b
  | _ => none

/-- The extracted target uses 64-bit pointer widths. -/
theorem package_member_contract (harch : System.Platform.numBits = 64) :
    PackageMemberRefines bytes runPackageMember := by
  intro path member hbound hmembers
  have hs : path.length ≤ 2^63 - 1 := by simpa [bytes] using hbound
  have hm : ∀ m, member = some m → m.length ≤ 2^63 - 1 := by
    intro m he
    simpa [bytes] using hmembers m he
  cases member <;> simp [runPackageMember, package_member_eq harch path _ hs hm, byte_values]

#print axioms archive_rel_contract
#print axioms package_member_contract

end Shirudo.AeneasPilot.Archive
