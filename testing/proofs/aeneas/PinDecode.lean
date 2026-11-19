-- SPDX-License-Identifier: BSD-2-Clause
-- Copyright (c) 2026 Authors of shirudo

import PinCodec
import PinCodecGenerated.Funs

namespace Shirudo.AeneasPilot.PinCodec

open Aeneas Aeneas.Std Aeneas.Std.WP

def DecodeLoopInv (decoded : Option (List Nat))
    (state : core.slice.iter.Iter U8 × alloc.vec.Vec U8) : Prop :=
  state.1.i ≤ state.1.slice.val.length ∧
    state.2.val.length + (state.1.slice.val.length - state.1.i) ≤ 255 ∧
    (PinName.decode (byteValues (state.1.slice.val.drop state.1.i))).map
      (byteValues state.2.val ++ ·) = decoded

theorem next_present (it : core.slice.iter.Iter U8)
    (h : it.i < it.slice.val.length) :
    core.slice.iter.IteratorSliceIter.next it =
      .ok (some it.slice.val[it.i], { it with i := it.i + 1 }) := by
  unfold core.slice.iter.IteratorSliceIter.next
  split
  · rfl
  · rename_i hn
    exact False.elim (hn (by simpa using h))

theorem next_absent (it : core.slice.iter.Iter U8)
    (h : ¬ it.i < it.slice.val.length) :
    core.slice.iter.IteratorSliceIter.next it = .ok (none, it) := by
  unfold core.slice.iter.IteratorSliceIter.next
  split
  · rename_i hn
    exact False.elim (h (by simpa using hn))
  · rfl

theorem name_from_pin_loop_refines
    (it : core.slice.iter.Iter U8) (out : alloc.vec.Vec U8)
    (decoded : Option (List Nat)) (hinv : DecodeLoopInv decoded (it, out)) :
    pin_codec.subject.name_from_pin_loop it out ⦃ result =>
      result.map (fun bytes => byteValues bytes.val) = decoded ⦄ := by
  unfold pin_codec.subject.name_from_pin_loop
  apply loop.spec_decr_nat (fun state => state.1.slice.val.length - state.1.i)
    (DecodeLoopInv decoded) _ _ _ ?_ hinv
  rintro ⟨it, out⟩ ⟨hi, hsize, he⟩
  dsimp only at hi hsize he
  unfold pin_codec.subject.name_from_pin_loop.body
  dsimp only
  by_cases hn : it.i < it.slice.val.length
  · rw [next_present it hn]
    simp only [bind_ok, uncurry]
    have hdrop := List.drop_eq_getElem_cons hn
    rw [hdrop] at he
    simp only [byteValues, List.map_cons] at he
    split
    · rename_i hc
      have hval : (it.slice.val[it.i]).val ≠ PinName.tilde := by
        intro hv
        have hb : it.slice.val[it.i] = 126#u8 := by
          apply UScalar.eq_of_val_eq
          simpa [PinName.tilde] using hv
        simp [hb] at hc
      rw [PinName.decode_other _ _ hval] at he
      have hroom : out.val.length < Usize.max := by scalar_tac
      apply WP.spec_bind (alloc.vec.Vec.push_spec out _ hroom)
      intro pushed hpushed
      simp only [WP.spec_ok, DecodeLoopInv]
      refine ⟨⟨by agrind, ?_, ?_⟩, by agrind⟩
      · simp [hpushed]
        agrind
      · simpa [hpushed, byteValues, List.map_append, Option.map_map,
          Function.comp_def, List.append_assoc] using he
    · rename_i hc
      have hval : (it.slice.val[it.i]).val = PinName.tilde := by
        simpa [PinName.tilde] using hc
      by_cases hn2 : it.i + 1 < it.slice.val.length
      · rw [next_present _ hn2]
        simp only [bind_ok, uncurry]
        have hdrop2 := List.drop_eq_getElem_cons hn2
        rw [hdrop2] at he
        simp only [List.map_cons] at he
        simp only [core.option.Option.Insts.CoreCmpPartialEqOption.eq,
          core.cmp.impls.PartialEqShared.eq, liftFun2, bind_ok]
        split
        · rename_i hd
          have hdval : (it.slice.val[it.i + 1]).val = PinName.letterD := by
            have hb : it.slice.val[it.i + 1] = 100#u8 := by
              simpa [core.cmp.impls.PartialEqU8.eq] using hd
            simpa [PinName.letterD] using congrArg UScalar.val hb
          simp only [PinName.decode, hval, hdval, ite_true] at he
          have hroom : out.val.length < Usize.max := by scalar_tac
          apply WP.spec_bind (alloc.vec.Vec.push_spec out _ hroom)
          intro pushed hpushed
          simp only [WP.spec_ok, DecodeLoopInv]
          refine ⟨⟨by agrind, ?_, ?_⟩, by agrind⟩
          · simp [hpushed]
            agrind
          · simpa [hpushed, byteValues, List.map_append, Option.map_map,
              Function.comp_def, List.append_assoc, PinName.dot, Nat.add_assoc] using he
        · rename_i hd
          have hdval : (it.slice.val[it.i + 1]).val ≠ PinName.letterD := by
            simpa [core.cmp.impls.PartialEqU8.eq, PinName.letterD] using hd
          simpa [PinName.decode, hval, hdval] using he
      · rw [next_absent _ hn2]
        have hempty : it.slice.val.drop (it.i + 1) = [] :=
          List.drop_eq_nil_of_le (by agrind)
        rw [hempty] at he
        simpa [PinName.decode, hval,
          core.option.Option.Insts.CoreCmpPartialEqOption.eq] using he
  · rw [next_absent it hn]
    have hend : it.i = it.slice.val.length := by agrind
    simpa [hend, byteValues, PinName.decode] using he

/-- The unchanged Rust decoder terminates successfully and agrees with the
pure decoder, including malformed escapes returned as Rust `None`. -/
theorem decode_refines : DecodeRefines pin_codec.subject.name_from_pin := by
  intro pin hsize
  unfold pin_codec.subject.name_from_pin
  simp only [core.slice.Slice.iter, bind_ok]
  apply name_from_pin_loop_refines
  simp [DecodeLoopInv, alloc.vec.Vec.with_capacity, byteValues, hsize]

#print axioms decode_refines

end Shirudo.AeneasPilot.PinCodec
