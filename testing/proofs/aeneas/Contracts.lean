-- SPDX-License-Identifier: BSD-2-Clause
-- Copyright (c) 2026 Authors of shirudo

import Shirudo.ArchivePath
import Shirudo.ConfigActivation

/-!
Refinement obligations, not proofs of the Rust predicates. After extraction,
instantiate these with projections from the generated types and runners that
map Aeneas success to `some` and failure or divergence to `none`.
-/

namespace Shirudo.AeneasPilot

abbrev Bytes := List (Fin 256)

/-- Only the production fields read by `same_event`. -/
structure Fields where
  sequence : Nat
  resetCount : Nat
  restartCount : Nat
  pcr : Nat
  kind : Int
  initial : Bytes
  root : Bytes
  deriving DecidableEq

/-- A superset of the records accepted by `record_decode`. -/
def Decoded (r : Fields) : Prop :=
  0 < r.sequence ∧ r.sequence ≤ 2^63 - 1 ∧
    r.resetCount < 2^32 ∧ r.restartCount < 2^32 ∧
    r.pcr < 16 ∧ r.pcr ≠ 9 ∧ r.pcr ≠ 11 ∧
    (r.kind = 1 ∨ r.kind = 2) ∧ r.initial.length = 32 ∧ r.root.length = 32

/-- A raw PCR value is one atom here, not a history of PCR extensions.
This specialization connects equality predicates only. -/
def event (r : Fields) : ConfigActivation.Event (Nat × Nat) Bytes Bytes where
  seq := r.sequence
  boot := (r.resetCount, r.restartCount)
  pcr := r.pcr
  kind := if r.kind = 1 then .boot else .update
  initial := [r.initial]
  root := r.root

/-- Sequence zero is the initial sentinel; decoded records are nonzero. -/
def previousEvent (r : Fields) : Option (ConfigActivation.Event (Nat × Nat) Bytes Bytes) :=
  if r.sequence = 0 then none else some (event r)

def SameEventRefines {Record : Type} (fields : Record → Fields)
    (run : Record → Record → Option Bool) : Prop :=
  ∀ a b, run a b = some (decide (fields a = fields b))

def EventProjectionFaithful : Prop :=
  ∀ a b, Decoded a → Decoded b → (a = b ↔ event a = event b)

/-- Both success and the exact Linux `-EUCLEAN` refusal, without wraparound
on decoded sequences. No assertion about the journal protocol is made. -/
def EventFollowsRefines {Record : Type} (fields : Record → Fields)
    (run : Record → Record → Option Int) : Prop :=
  ∀ previous record,
    ((fields previous).sequence = 0 ∨ Decoded (fields previous)) →
    Decoded (fields record) →
    run previous record = some
      (if ConfigActivation.Follows (previousEvent (fields previous))
          (event (fields record)) then 0 else -117)

def byteValues (bytes : Bytes) : List Nat := bytes.map Fin.val

/-- Explicit Rust slices: NUL is an ordinary byte for these predicates.
The filesystem interpretation additionally requires NUL-free inputs. -/
def ArchiveRelRefines {Slice : Type} (bytes : Slice → Bytes)
    (run : Slice → Option Bool) : Prop :=
  ∀ name, (bytes name).length ≤ 2^63 - 1 →
    run name = some (ArchivePath.relOk (byteValues (bytes name)))

def PackageMemberRefines {Slice : Type} (bytes : Slice → Bytes)
    (run : Slice → Option Slice → Option Bool) : Prop :=
  ∀ name member, (bytes name).length ≤ 2^63 - 1 →
    (∀ m, member = some m → (bytes m).length ≤ 2^63 - 1) →
    run name member = some (match member with
      | none => false
      | some m => ArchivePath.memberNameOk
          (byteValues (bytes name)) (byteValues (bytes m)))

end Shirudo.AeneasPilot
