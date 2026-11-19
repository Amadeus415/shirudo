-- SPDX-License-Identifier: BSD-2-Clause
-- Copyright (c) 2026 Authors of shirudo

import PinEncodeGenerated.Funs
import Shirudo.PinName

/-!
The byte-slice codec in `rust/src/util/upatch.rs`, compared with the pure
`PinName.encode` and `PinName.decode` models. These functions do not append
or consume a NUL terminator. Applying the result to a C string requires
the caller's bytes before its NUL. Allocation exhaustion is outside the
Aeneas vector model.
-/

namespace Shirudo.AeneasPilot.PinCodec

open Aeneas Aeneas.Std Aeneas.Std.WP

def byteValues (bytes : List U8) : List Nat := bytes.map UScalar.val

/-- The encoded-length bound required by the production name validator. -/
def NameFits (input : Slice U8) : Prop :=
  (PinName.encode (byteValues input.val)).length ≤ 255

/-- The exact result of the generated encoder under the pin-length bound. -/
def EncodeRefines : Prop :=
  ∀ input, NameFits input →
    pin_encode.subject.pin_name input ⦃ encoded =>
      byteValues encoded.val = PinName.encode (byteValues input.val) ⦄

/-- Exact decoding, including Rust `None` for malformed escapes.
A successful Rust `None` differs from Aeneas failure or divergence. -/
def DecodeRefines (decode : Slice U8 → Result (Option (alloc.vec.Vec U8))) : Prop :=
  ∀ pin : Slice U8, pin.val.length ≤ 255 →
    decode pin ⦃ decoded =>
      decoded.map (fun input => byteValues input.val) =
        PinName.decode (byteValues pin.val) ⦄

private def LoopInv (encoded : List Nat)
    (state : core.slice.iter.Iter U8 × alloc.vec.Vec U8) : Prop :=
  state.1.i ≤ state.1.slice.val.length ∧
    byteValues state.2.val ++
      PinName.encode (byteValues (state.1.slice.val.drop state.1.i)) = encoded

private theorem extend_bytes (out : alloc.vec.Vec U8) (suffix : Slice U8)
    (hroom : out.length + suffix.length ≤ Usize.max) :
    alloc.vec.Vec.extend_from_slice core.clone.CloneU8 out suffix ⦃ result =>
      result.val = out.val ++ suffix.val ⦄ := by
  unfold alloc.vec.Vec.extend_from_slice
  rw [dite_eq_left hroom]
  apply WP.spec_bind (List.clone_spec (by intros; rfl))
  intro cloned hcloned
  simp only [WP.spec_ok, alloc.vec.Vec.from_val, hcloned.1]

private theorem pin_name_loop_refines
    (iter : core.slice.iter.Iter U8) (out : alloc.vec.Vec U8)
    (encoded : List Nat) (hsize : encoded.length ≤ 255)
    (hinv : LoopInv encoded (iter, out)) :
    pin_encode.subject.pin_name_loop iter out ⦃ result =>
      byteValues result.val = encoded ⦄ := by
  unfold pin_encode.subject.pin_name_loop
  apply loop.spec_decr_nat (fun state => state.1.slice.val.length - state.1.i)
    (LoopInv encoded) _ _ _ ?_ hinv
  rintro ⟨iter, out⟩ ⟨hi, he⟩
  dsimp only at hi he
  unfold pin_encode.subject.pin_name_loop.body
  dsimp only
  by_cases hnext : iter.i < iter.slice.val.length
  · have hdrop := List.drop_eq_getElem_cons hnext
    rw [hdrop] at he
    simp only [byteValues, List.map_cons, PinName.encode_cons] at he
    have hlength := congrArg List.length he
    simp only [List.length_append, List.length_map] at hlength
    have hn : core.slice.iter.IteratorSliceIter.next iter =
        Result.ok (some iter.slice.val[iter.i], { iter with i := iter.i + 1 }) := by
      unfold core.slice.iter.IteratorSliceIter.next
      split
      · rfl
      · rename_i hstop
        exfalso
        apply hstop
        simpa using hnext
    rw [hn]
    simp only [bind_ok, uncurry]
    split
    · rename_i hdot
      have hc : (iter.slice.val[iter.i]).val = PinName.dot := by
        simpa [PinName.dot] using congrArg UScalar.val hdot
      have hroom : out.val.length + 2 ≤ Usize.max := by
        simp only [hc, PinName.encodeByte, ite_true, List.length_cons,
          List.length_nil] at hlength
        scalar_tac
      simp only [lift, bind_ok]
      apply WP.spec_bind (extend_bytes out _ (by
        simpa [Array.to_slice, Array.make] using hroom))
      intro extended hextended
      simp only [WP.spec_ok, LoopInv]
      refine ⟨⟨by agrind, ?_⟩, by agrind⟩
      simpa [hextended, Array.to_slice, Array.make, byteValues, List.map_append,
        List.append_assoc, hc, PinName.encodeByte, PinName.tilde, PinName.letterD] using he
    · rename_i hdot
      have hc : (iter.slice.val[iter.i]).val ≠ PinName.dot := by
        intro hc
        apply hdot
        apply UScalar.eq_of_val_eq
        simpa [PinName.dot] using hc
      have hroom : out.val.length < Usize.max := by
        simp only [PinName.encodeByte, hc, ite_false, List.length_cons,
          List.length_nil] at hlength
        scalar_tac
      apply WP.spec_bind (alloc.vec.Vec.push_spec out _ hroom)
      intro pushed hpushed
      simp only [WP.spec_ok, LoopInv]
      refine ⟨⟨by agrind, ?_⟩, by agrind⟩
      simpa [hpushed, byteValues, List.map_append, List.append_assoc,
        PinName.encodeByte, hc] using he
  · have hend : iter.i = iter.slice.val.length := by agrind
    simpa [core.slice.iter.IteratorSliceIter.next, hnext, hend, byteValues, PinName.encode]
      using he

theorem encode_refines : EncodeRefines := by
  intro input hsize
  unfold pin_encode.subject.pin_name
  simp only [SharedSlice.Insts.CoreIterTraitsCollectIntoIteratorSharedIter.into_iter,
    bind_ok]
  apply pin_name_loop_refines _ _ _ hsize
  simp [LoopInv, alloc.vec.Vec.with_capacity, byteValues]

/-- The existing pure decoder reverses the generated encoder for names
without `~`. This does not establish a theorem about the Rust decoder. -/
theorem encode_model_round_trip (input : Slice U8) (hsize : NameFits input)
    (htilde : PinName.tilde ∉ byteValues input.val) :
    pin_encode.subject.pin_name input ⦃ encoded =>
      PinName.decode (byteValues encoded.val) = some (byteValues input.val) ⦄ := by
  apply WP.spec_mono (encode_refines input hsize)
  intro encoded he
  rw [he]
  exact PinName.decode_encode _ htilde

theorem encode_no_dot (input : Slice U8) (hsize : NameFits input) :
    pin_encode.subject.pin_name input ⦃ encoded =>
      PinName.dot ∉ byteValues encoded.val ⦄ := by
  apply WP.spec_mono (encode_refines input hsize)
  intro encoded he
  rw [he]
  exact PinName.dot_not_mem_encode _

theorem encode_collision_free (a b : Slice U8)
    (ha : NameFits a) (hb : NameFits b)
    (hta : PinName.tilde ∉ byteValues a.val)
    (htb : PinName.tilde ∉ byteValues b.val) :
    (do
      let ea ← pin_encode.subject.pin_name a
      let eb ← pin_encode.subject.pin_name b
      pure (ea, eb)) ⦃ ea eb =>
        byteValues ea.val = byteValues eb.val → byteValues a.val = byteValues b.val ⦄ := by
  apply WP.spec_bind (encode_refines a ha)
  intro ea hea
  apply WP.spec_bind (encode_refines b hb)
  intro eb heb
  simp only [pure, WP.spec_ok, uncurry'_pair]
  intro he
  rw [hea, heb] at he
  exact PinName.encode_injective _ _ hta htb he

#print axioms encode_refines
#print axioms encode_model_round_trip
#print axioms encode_no_dot
#print axioms encode_collision_free

end Shirudo.AeneasPilot.PinCodec
