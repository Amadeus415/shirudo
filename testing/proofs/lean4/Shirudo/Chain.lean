-- SPDX-License-Identifier: BSD-2-Clause
-- Copyright (c) 2026 Authors of shirudo

/-!
The measurement register of rust/src/util/chain.rs. Each upatch state
change extends it as `H(register ‖ event)`, the way a TPM extends a PCR,
with an event that hashes a domain-separating tag and its payload.
`attest verify` replays the eventlog and compares the result with the
register the TPM signed. Assuming `H` is collision resistant, modelled as
injective on (register, event) pairs and never yielding the initial
value, and the tagged encoding of events likewise, equal registers mean
the target measured exactly the events the log shows, in that order.
`register_injective_on` asks the same of `H` only on the pairs the two
sequences fold, which a real hash can meet; `Shirudo.Events` proves the
encodings of rust/src/util/chain.rs injective and builds the end theorem
on it.
-/

namespace Shirudo.Chain

variable {D K P : Type}

/-- The register after `events`, the newest first. -/
def register (H : D → D → D) (init : D) : List D → D
  | [] => init
  | e :: es => H (register H init es) e

/-- The same register, folded over the events in the order they came. -/
theorem register_eq_foldl (H : D → D → D) (init : D) (events : List D) :
    register H init events = events.reverse.foldl H init := by
  induction events with
  | nil => rfl
  | cons e es ih => simp [register, ih]

/-- Equal registers come from equal event sequences. -/
theorem register_injective (H : D → D → D) (init : D)
    (hH : ∀ a b c d, H a b = H c d → a = c ∧ b = d)
    (hinit : ∀ a b, H a b ≠ init) :
    ∀ l1 l2 : List D, register H init l1 = register H init l2 → l1 = l2
  | [], [], _ => rfl
  | [], f :: fs, h => absurd h.symm (hinit _ f)
  | e :: es, [], h => absurd h (hinit _ e)
  | e :: es, f :: fs, h => by
    have ⟨hr, he⟩ := hH _ _ _ _ h
    rw [he, register_injective H init hH hinit es fs hr]

/-- The (register, event) pairs `H` folds on the way to the register of
`events`, newest first. -/
def steps (H : D → D → D) (init : D) : List D → List (D × D)
  | [] => []
  | e :: es => (register H init es, e) :: steps H init es

/-- Equal registers come from equal event sequences when `H` maps no two
of the pairs the two sequences fold to one value, and none of them to the
initial value. Unlike `register_injective`, this asks nothing of `H` on
pairs neither sequence folds, which a hash with a 32-byte output can
meet. -/
theorem register_injective_on (H : D → D → D) (init : D) :
    ∀ l1 l2 : List D,
      (∀ p ∈ steps H init l1, ∀ q ∈ steps H init l2,
        H p.1 p.2 = H q.1 q.2 → p = q) →
      (∀ p ∈ steps H init l1 ++ steps H init l2, H p.1 p.2 ≠ init) →
      register H init l1 = register H init l2 → l1 = l2
  | [], [], _, _, _ => rfl
  | [], f :: fs, _, hinit, h =>
    absurd h.symm (hinit (register H init fs, f) (by simp [steps]))
  | e :: es, [], _, hinit, h =>
    absurd h (hinit (register H init es, e) (by simp [steps]))
  | e :: es, f :: fs, hH, hinit, h => by
    have hp := hH (register H init es, e) (by simp [steps])
      (register H init fs, f) (by simp [steps]) h
    simp only [Prod.mk.injEq] at hp
    have hrest : es = fs :=
      register_injective_on H init es fs
        (fun p hp' q hq => hH p (by simp [steps, hp']) q (by simp [steps, hq]))
        (fun p hp' => hinit p (by
          simp only [List.mem_append] at hp' ⊢
          rcases hp' with hp' | hp'
          · exact Or.inl (by simp [steps, hp'])
          · exact Or.inr (by simp [steps, hp'])))
        hp.1
    rw [hp.2, hrest]

theorem map_injective {α β : Type} (f : α → β) (hf : Function.Injective f) :
    ∀ l1 l2 : List α, l1.map f = l2.map f → l1 = l2
  | [], [], _ => rfl
  | [], _ :: _, h => by simp at h
  | _ :: _, [], h => by simp at h
  | a :: as, b :: bs, h => by
    simp only [List.map_cons, List.cons.injEq] at h
    rw [hf h.1, map_injective f hf as bs h.2]

/-- `map_injective` for an `f` injective only between the elements of the
two lists. -/
theorem map_injective_on {α β : Type} (f : α → β) :
    ∀ l1 l2 : List α, (∀ a ∈ l1, ∀ b ∈ l2, f a = f b → a = b) →
      l1.map f = l2.map f → l1 = l2
  | [], [], _, _ => rfl
  | [], _ :: _, _, h => by simp at h
  | _ :: _, [], _, h => by simp at h
  | a :: as, b :: bs, hf, h => by
    simp only [List.map_cons, List.cons.injEq] at h
    rw [hf a (by simp) b (by simp) h.1,
      map_injective_on f as bs
        (fun x hx y hy => hf x (by simp [hx]) y (by simp [hy])) h.2]

/-- Equal registers come from the same tagged events, in the same order:
an event can be neither left out, added, swapped for another nor moved. -/
theorem register_tagged_injective (H : D → D → D) (init : D)
    (encode : K → P → D)
    (hH : ∀ a b c d, H a b = H c d → a = c ∧ b = d)
    (hinit : ∀ a b, H a b ≠ init)
    (henc : ∀ k p k' p', encode k p = encode k' p' → k = k' ∧ p = p')
    (l1 l2 : List (K × P))
    (h : register H init (l1.map fun e => encode e.1 e.2) =
      register H init (l2.map fun e => encode e.1 e.2)) :
    l1 = l2 := by
  have hinj : Function.Injective (fun e : K × P => encode e.1 e.2) := by
    intro ⟨k, p⟩ ⟨k', p'⟩ he
    have ⟨hk, hp⟩ := henc _ _ _ _ he
    subst hk; subst hp; rfl
  exact map_injective _ hinj _ _ (register_injective H init hH hinit _ _ h)

end Shirudo.Chain
