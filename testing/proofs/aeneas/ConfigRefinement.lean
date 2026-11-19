-- SPDX-License-Identifier: BSD-2-Clause
-- Copyright (c) 2026 Authors of shirudo

import ConfigPredicates.Funs
import Contracts

open Aeneas Aeneas.Std Result

namespace Shirudo.AeneasPilot.Config

abbrev Record := config_predicates.subject.ConfigUpdateRecord

def byte (x : U8) : Fin 256 := x.bv.toFin

def bytes (a : Aeneas.Std.Array U8 n) : Bytes := a.val.map byte

def fields (r : Record) : Fields where
  sequence := r.sequence.val
  resetCount := r.reset_count.val
  restartCount := r.restart_count.val
  pcr := r.pcr.val
  kind := r.kind.val
  initial := bytes r.initial_pcr
  root := bytes r.target.root_hash

private theorem allM_eq {α : Type} [DecidableEq α]
    (a b : List α) (hlen : a.length = b.length) :
    List.allM (fun p => ok (decide (p.1 = p.2))) (a.zip b) =
      ok (decide (a = b)) := by
  induction a generalizing b with
  | nil =>
    cases b <;> simp_all [pure]
  | cons x xs ih =>
    cases b with
    | nil => simp at hlen
    | cons y ys =>
      simp only [List.length_cons, Nat.add_right_cancel_iff] at hlen
      by_cases h : x = y
      · subst y
        simpa [List.allM, pure] using ih ys hlen
      · simp [pure, h]

private theorem array_eq (a b : Aeneas.Std.Array U8 n) :
    core.array.equality.PartialEqArray.eq core.cmp.PartialEqU8 a b =
      ok (decide (a = b)) := by
  have hlen : a.val.length = b.val.length := by simp
  calc
    _ = List.allM (fun p => ok (decide (p.1 = p.2))) (a.val.zip b.val) := by
      unfold core.array.equality.PartialEqArray.eq
      simp only [Aeneas.Std.Array.length, Array.property, ↓reduceIte]
      apply congrArg (fun f => List.allM f (a.val.zip b.val))
      funext p
      cases p
      simp [liftFun2, UScalar.eq_equiv]
    _ = ok (decide (a = b)) := by
      rw [allM_eq a.val b.val hlen]
      simp only [← Aeneas.Std.Array.eq_iff]

private theorem bytes_injective (a b : Aeneas.Std.Array U8 n) :
    bytes a = bytes b ↔ a = b := by
  constructor
  · intro h
    apply Aeneas.Std.Array.ext
    exact (List.map_inj_right (fun _ _ hxy =>
      UScalar.eq_of_val_eq (congrArg Fin.val hxy))).mp h
  · intro h
    cases h
    rfl

theorem fields_eq (a b : Record) : fields a = fields b ↔
    a.reset_count = b.reset_count ∧ a.restart_count = b.restart_count ∧
    a.sequence = b.sequence ∧ a.pcr = b.pcr ∧ a.kind = b.kind ∧
    a.initial_pcr = b.initial_pcr ∧ a.target.root_hash = b.target.root_hash := by
  simp only [fields, Fields.mk.injEq, bytes_injective,
    ← UScalar.eq_equiv, ← IScalar.eq_equiv]
  simp only [and_left_comm]

theorem same_event_refines (a b : Record) :
    config_predicates.subject.same_event a b = ok (decide (fields a = fields b)) := by
  simp only [config_predicates.subject.same_event, config_predicates.subject.same_boot,
    config_predicates.subject.ConfigUpdateRecord.boot,
    config_predicates.subject.BootIdentity.Insts.CoreCmpPartialEqBootIdentity.eq,
    bind_ok,
    array_eq, fields_eq]
  repeat' split <;> simp_all

def runSameEvent (a b : Record) : Option Bool :=
  match (config_predicates.subject.same_event a b).match with
  | .ok result => some result
  | _ => none

theorem same_event_contract : SameEventRefines fields runSameEvent := by
  intro a b
  simp [runSameEvent, same_event_refines]

theorem event_projection_faithful : EventProjectionFaithful := by
  intro a b ha hb
  cases a
  cases b
  rcases ha with ⟨_, _, _, _, _, _, _, hak, _, _⟩
  rcases hb with ⟨_, _, _, _, _, _, _, hbk, _, _⟩
  rcases hak with ha | ha <;> rcases hbk with hb | hb <;>
    simp_all [event, Fields.mk.injEq, ConfigActivation.Event.mk.injEq]

theorem event_follows_refines (previous record : Record)
    (hp : (fields previous).sequence = 0 ∨ Decoded (fields previous))
    (hr : Decoded (fields record)) :
    config_predicates.subject.event_follows previous record = ok
      (if ConfigActivation.Follows (previousEvent (fields previous))
          (event (fields record)) then core.result.Result.Ok ()
       else core.result.Result.Err ((-117)#i32)) := by
  have bound : previous.sequence.val ≤ 9223372036854775807 := by
    rcases hp with hp | hp
    · change previous.sequence.val = 0 at hp
      agrind
    · exact hp.2.1
  have wrap : (core.num.U64.wrapping_add previous.sequence 1#u64).val =
      previous.sequence.val + 1 := by
    rw [core.num.U64.wrapping_add_val_eq]
    apply Nat.mod_eq_of_lt
    have one : (1#u64).val = 1 := by decide
    have size : UScalar.size .U64 = 18446744073709551616 := by
      simp [UScalar.size_def, UScalarTy.numBits]
    rw [one, size]
    agrind
  have negclean : (-. config_predicates.subject.EUCLEAN : Result I32) =
      ok ((-117)#i32) := by
    simp [HNeg.hNeg, config_predicates.subject.EUCLEAN, IScalar.neg,
      IScalar.tryMk, IScalar.tryMkOpt, IScalar.check_bounds]
  have kinds := hr.2.2.2.2.2.2.2.1
  change record.kind.val = 1 ∨ record.kind.val = 2 at kinds
  simp only [config_predicates.subject.event_follows,
    config_predicates.subject.same_boot,
    config_predicates.subject.ConfigUpdateRecord.boot,
    config_predicates.subject.BootIdentity.Insts.CoreCmpPartialEqBootIdentity.eq,
    bind_ok, core.array.equality.PartialEqArray.ne,
    array_eq, lift, bind_tc_ok, negclean]
  rcases kinds with hk | hk <;>
    by_cases hz : previous.sequence.val = 0 <;>
    simp [previousEvent, event, fields, ConfigActivation.Follows,
      config_predicates.subject.EVENT_BOOT, config_predicates.subject.EVENT_UPDATE,
      UScalar.eq_equiv, IScalar.eq_equiv, bytes_injective, wrap, hk, hz] <;>
    repeat' split <;> simp_all

def runEventFollows (previous record : Record) : Option Int :=
  match (config_predicates.subject.event_follows previous record).match with
  | .ok (.Ok ()) => some 0
  | .ok (.Err error) => some error.val
  | _ => none

theorem event_follows_contract : EventFollowsRefines fields runEventFollows := by
  intro previous record hp hr
  by_cases hf : ConfigActivation.Follows (previousEvent (fields previous)) (event (fields record))
  all_goals simp [runEventFollows, event_follows_refines previous record hp hr, hf]

#print axioms same_event_contract
#print axioms event_projection_faithful
#print axioms event_follows_contract

end Shirudo.AeneasPilot.Config
