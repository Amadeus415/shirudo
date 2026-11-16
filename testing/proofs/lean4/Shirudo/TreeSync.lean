-- SPDX-License-Identifier: BSD-2-Clause
-- Copyright (c) 2026 Authors of shirudo

import Shirudo.Chain

/-!
`bpm tree sync`, `cmd_bpm_tree_sync()` of builtin-bpm.c. It reads the
node's state, fetches a signed tree publication, refuses one that
`tree_parse()`, `tree_publication_check()`, `tree_operation_validate()` or
`tree_publication_follows()` refuses, and runs `tree_recover_pending()`.
Then, for each operation past the cursor that its selector matches, it
writes `pending.json`, installs the upatch, extends the register and records
the `tree_op` event, appends a line to the tree eventlog, writes the state
with the new cursor and projection root and unlinks `pending.json`; one the
selector does not match moves the cursor. At the end it writes the state
with the publication's generation and manifest digest.

The model follows the C step by step: a node is its four files, a sync the
list of writes it makes, each atomic, and a crash or a refusal after some of
them the writes before it. Root picks every input: any publication the
node's key signed, in any manifest a registry wraps it in, the selector's
answers, where each sync stops, and reboots, which start this boot's
records afresh. `Later` orders every two points of the node's history,
those inside one sync included.

For every such history the node never goes back: the generation and the
cursor never decrease and the tree eventlog only grows (`generation_mono`,
`lastSeq_mono`, `log_grows`); at an equal generation only the recorded
manifest is held (`manifest_fixed`); a publication of an earlier generation
than one the node accepted is refused (`accepted_older_refused`). Each
operation is applied at most once, in increasing order, in the tree eventlog
and in this boot's records (`log_increasing`, `measured_increasing`). After a
crash between writing `pending.json` and committing the state, recovery
appends the pending operation exactly when this boot measured it or its line
is there, at most once, and otherwise leaves the cursor below it
(`recover_pending`); nothing measured is lost (`measured_kept`). The state is
the fold of the operations the tree eventlog records, but in the window
between appending a line and writing the state (`state_is_fold`), which
recovery closes (`recover_settles`). Every applied operation is one of a
signed publication of the node's tree (`applied_signed`), and the one every
such publication has at its number when the signer never gives a number two
operations (`applied_consistent`).

The generation rests on the generation check of `Follows`, on `tree_parse()`
refusing a negative generation, as a first sync writes generation 0 before
its last write, and on a manifest digest naming one publication. The cursor
and the order rest on the loop's own cursor check and recovery's; that each
operation is applied once rests on recovery's comparison of the replayed
root and on its look at this boot's records, with the hash collision
resistant. The cursor check and the parent check of `Follows` and the rest
of what `tree_parse()` and `tree_publication_check()` require are not needed
by any of these theorems. `Assumptions` states what the C cannot show.

The model also assumes what review of the C shows: only sync writes these
files, which the seal ensures; a write is whole or absent, as
`seal_write_file()` renames and `append_line()` drops a line it did not
finish; syncs run one at a time under the BPM lock; the unlink of
`pending.json`, whose result sync ignores, succeeds; and an extend with its
eventlog record is one write, as a stop between them leaves the register
ahead of the log. Installing or removing the upatch writes nothing the model
holds: it succeeds or stops the sync. A stop after an install and before its
measure leaves the operation pending and unmeasured, so the next sync
applies it again, and that goes on to measure it: `upatch_install()` takes
the payload already loaded under the name as installed, and
`upatch_remove()` an upatch already gone as removed.
The CBMC harnesses bpm-tree-follows.c, which proved
`tree_publication_follows()` is `Follows`, and bpm-tree-sync-model.c, which
checked the writes of `cmd_bpm_tree_sync()` against `run` for publications
of up to two operations, went with util/bpm_tree.c when it moved to
rust/src/util/bpm_tree.rs.
-/

namespace Shirudo.TreeSync
open Shirudo

/-! ### What the node and a publication hold -/

/-- An operation of `struct tree_operation`, as far as sync reads it: its
sequence number, upatch name and operation digest, the 32 bytes
`sha256_digest_decode()` takes from its `sha256:` string. The pending record,
`struct tree_pending`, holds the same three fields. -/
structure Op (I D : Type) where
  seq : Int
  id : I
  digest : D
deriving DecidableEq

/-- `struct tree_publication`; `parent` is `none` for an empty
`parent_manifest_digest`. -/
structure Pub (T M I D : Type) where
  treeId : T
  generation : Int
  parent : Option M
  baseSeq : Int
  ops : List (Op I D)
  headSeq : Int

/-- `struct tree_state`: `root` is `projection_root`, which sync writes into
`projection_root_tpm` too, and `manifest` is `none` for an empty
`manifest_digest`. -/
structure State (T M D : Type) where
  treeId : T
  generation : Int
  lastSeq : Int
  root : D
  manifest : Option M

/-- A line `tree_event_append()` adds to the tree eventlog. -/
structure Line (D : Type) where
  seq : Int
  digest : D
  root : D

/-- What sync reads and writes on the node: `state.json`, `pending.json`, the
tree eventlog, oldest line first, and the `tree_op` records of this boot's
eventlog, the ones `eventlog_tree_op_measured()` reads. `none` and `[]` are
files that do not exist. -/
structure Node (T M I D : Type) where
  state : Option (State T M D)
  pending : Option (Op I D)
  log : List (Line D)
  measured : List (Int × D)

/-- The writes of a sync, each atomic: `tree_pending_write()`, the extend
and eventlog record of `tree_measure_operation()`, `tree_event_append()`,
`tree_state_write()` and the unlink of `pending.json`. -/
inductive Write (T M I D : Type) where
  | pending (o : Op I D)
  | measure (seq : Int) (d : D)
  | append (l : Line D)
  | state (s : State T M D)
  | unlink

variable {T M I D : Type}

/-- The node after one write. -/
def Write.apply : Write T M I D → Node T M I D → Node T M I D
  | .pending o, n => { n with pending := some o }
  | .measure s d, n => { n with measured := n.measured ++ [(s, d)] }
  | .append l, n => { n with log := n.log ++ [l] }
  | .state s, n => { n with state := some s }
  | .unlink, n => { n with pending := none }

/-- The node after the writes `ws`, in order. -/
def applyAll (ws : List (Write T M I D)) (n : Node T M I D) : Node T M I D :=
  ws.foldl (fun n w => w.apply n) n

/-- The node before its first sync. -/
def Node.empty : Node T M I D := ⟨none, none, [], []⟩

/-! ### The checks before anything is applied -/

/-- What `tree_parse()` and `tree_publication_check()` require of a
publication's numbers: a generation of 0 or more, a base of 0, and
operations numbered from base + 1 to head without a gap. -/
def Checked (pub : Pub T M I D) : Prop :=
  0 ≤ pub.generation ∧ pub.baseSeq = 0 ∧
    pub.headSeq = pub.baseSeq + pub.ops.length ∧
    pub.ops.map (·.seq) =
      (List.range pub.ops.length).map
        (fun i : Nat => pub.baseSeq + 1 + (i : Int))

instance (pub : Pub T M I D) : Decidable (Checked pub) := by
  unfold Checked; infer_instance

/-- `tree_publication_follows()`, as the CBMC harness `bpm-tree-follows.c`
stated it and proved the C met for every `__s64` before the function moved
to rust/src/util/bpm_tree.rs: without a state, a base of 0; with
one, the same tree, a later generation unless it is the same manifest, the
recorded manifest as parent when it is the next generation and names one,
and the cursor between base and head. -/
def Follows [DecidableEq T] [DecidableEq M] (pub : Pub T M I D) :
    Option (State T M D) → M → Prop
  | none, _ => pub.baseSeq = 0
  | some s, m =>
    s.treeId = pub.treeId ∧
    (s.manifest = some m ∨ s.generation < pub.generation) ∧
    (s.manifest = some m ∨ pub.generation ≠ s.generation + 1 ∨
      pub.parent = none ∨ pub.parent = s.manifest) ∧
    pub.baseSeq ≤ s.lastSeq ∧ s.lastSeq ≤ pub.headSeq

instance [DecidableEq T] [DecidableEq M] (pub : Pub T M I D)
    (st : Option (State T M D)) (m : M) : Decidable (Follows pub st m) := by
  cases st <;> unfold Follows <;> infer_instance

section hash
variable (H : D → D → D) (init : D)

/-- The projection root of the lines `log`: it starts at 64 zeros, `init`,
and each operation takes it to `SHA256(root ‖ digest)`. -/
def rootOf (log : List (Line D)) : D :=
  (log.map (·.digest)).foldl H init

/-- The root of the lines `log` with one more line. -/
theorem rootOf_append (log : List (Line D)) (l : Line D) :
    rootOf H init (log ++ [l]) = H (rootOf H init log) l.digest := by
  simp [rootOf, List.foldl_append]

/-- No operation leaves the projection root where it was, so a root tells
whether the line of an operation is there: the hash is collision
resistant, modelled as `Shirudo.Chain` models it. -/
theorem rootOf_ne_next (hH : ∀ a b c d, H a b = H c d → a = c ∧ b = d)
    (hinit : ∀ a b, H a b ≠ init) (log : List (Line D)) (d : D) :
    rootOf H init log ≠ H (rootOf H init log) d := by
  intro h
  have hr : ∀ L : List (Line D),
      rootOf H init L = Chain.register H init (L.map (·.digest)).reverse := by
    intro L
    rw [Chain.register_eq_foldl, List.reverse_reverse]
    rfl
  rw [hr] at h
  have h' : Chain.register H init (log.map (·.digest)).reverse =
      Chain.register H init (d :: (log.map (·.digest)).reverse) := h
  have := Chain.register_injective H init hH hinit _ _ h'
  have hl := congrArg List.length this
  simp at hl

end hash

/-! ### Runs stopped after any write -/

/-- `P` holds of the node before each write of `ws` and after the last,
and `R` of the node before and after each write. -/
def Along (P : Node T M I D → Prop) (R : Node T M I D → Node T M I D → Prop) :
    List (Write T M I D) → Node T M I D → Prop
  | [], n => P n
  | w :: ws, n => P n ∧ R n (w.apply n) ∧ Along P R ws (w.apply n)

theorem applyAll_nil (n : Node T M I D) : applyAll [] n = n := rfl

theorem applyAll_cons (w : Write T M I D) (ws : List (Write T M I D))
    (n : Node T M I D) :
    applyAll (w :: ws) n = applyAll ws (w.apply n) := rfl

theorem applyAll_append (ws ws' : List (Write T M I D)) (n : Node T M I D) :
    applyAll (ws ++ ws') n = applyAll ws' (applyAll ws n) := by
  simp [applyAll, List.foldl_append]

theorem along_first {P : Node T M I D → Prop}
    {R : Node T M I D → Node T M I D → Prop}
    {ws : List (Write T M I D)} {n : Node T M I D} (h : Along P R ws n) :
    P n := by
  cases ws <;> simp only [Along] at h
  · exact h
  · exact h.1

/-- `P` holds wherever the writes stop. -/
theorem along_take {P : Node T M I D → Prop}
    {R : Node T M I D → Node T M I D → Prop}
    {ws : List (Write T M I D)} {n : Node T M I D} (h : Along P R ws n)
    (k : Nat) :
    P (applyAll (ws.take k) n) := by
  induction ws generalizing n k with
  | nil => simp only [List.take_nil]; exact h
  | cons w ws ih =>
    cases k with
    | zero => exact along_first h
    | succ k =>
      simp only [Along] at h
      simpa [applyAll_cons] using ih h.2.2 k

/-- A relation that holds across each write, reflexive and transitive,
holds from any point of the writes to any later one. -/
theorem along_between {P : Node T M I D → Prop}
    {R : Node T M I D → Node T M I D → Prop}
    (hrefl : ∀ x, R x x) (htrans : ∀ a b c, R a b → R b c → R a c)
    {ws : List (Write T M I D)} {n : Node T M I D} (h : Along P R ws n) :
    ∀ i j, i ≤ j → R (applyAll (ws.take i) n) (applyAll (ws.take j) n) := by
  induction ws generalizing n with
  | nil => intro i j _; simp only [List.take_nil]; exact hrefl _
  | cons w ws ih =>
    simp only [Along] at h
    intro i j hij
    cases i with
    | zero =>
      cases j with
      | zero => exact hrefl _
      | succ j =>
        simp only [List.take_zero, List.take_succ_cons, applyAll_cons]
        exact htrans _ _ _ h.2.1 (ih h.2.2 0 j (Nat.zero_le _))
    | succ i =>
      cases j with
      | zero => omega
      | succ j =>
        simp only [List.take_succ_cons, applyAll_cons]
        exact ih h.2.2 i j (by omega)

theorem along_append {P : Node T M I D → Prop}
    {R : Node T M I D → Node T M I D → Prop}
    {ws ws' : List (Write T M I D)} {n : Node T M I D} (h : Along P R ws n)
    (h' : Along P R ws' (applyAll ws n)) : Along P R (ws ++ ws') n := by
  induction ws generalizing n with
  | nil => exact h'
  | cons w ws ih =>
    simp only [Along] at h ⊢
    exact ⟨h.1, h.2.1, ih h.2.2 h'⟩

/-! ### The tree eventlog -/

section replay
variable [DecidableEq D] (H : D → D → D) (init : D)

/-- The loop of `tree_event_replay()`, from the previous line's sequence
number and the chain: each line above the one before, and the root it
records the chain. -/
def replayFrom : Int → D → List (Line D) → Option (Int × D)
  | s, c, [] => some (s, c)
  | s, c, l :: ls =>
    if s < l.seq ∧ l.root = H c l.digest then replayFrom l.seq (H c l.digest) ls
    else none

/-- What `tree_event_replay()` returns: `-ENOENT`, `-EINVAL` or the root. -/
inductive Replay (D : Type) where
  | missing
  | bad
  | ok (root : D)

/-- `tree_event_replay()`. sync never writes an empty tree eventlog, and
`append_line()` drops a line an append did not finish, so the lines it
appended are what the file holds. -/
def replay : List (Line D) → Replay D
  | [] => .missing
  | l :: ls =>
    match replayFrom H 0 init (l :: ls) with
    | some (_, r) => .ok r
    | none => .bad

theorem replayFrom_append (s : Int) (c : D) (ls : List (Line D)) (l : Line D) :
    replayFrom H s c (ls ++ [l]) =
      match replayFrom H s c ls with
      | some (t, r) =>
        if t < l.seq ∧ l.root = H r l.digest then some (l.seq, H r l.digest)
        else none
      | none => none := by
  induction ls generalizing s c with
  | nil => simp [replayFrom]
  | cons x xs ih =>
    simp only [List.cons_append, replayFrom]
    split
    · exact ih _ _
    · rfl

/-- A replay that succeeds returns the root of the lines, and their
numbers rise from above where it started to where it ends. -/
theorem replayFrom_some {s : Int} {c : D} {ls : List (Line D)} {t : Int} {r : D}
    (h : replayFrom H s c ls = some (t, r)) :
    r = (ls.map (·.digest)).foldl H c ∧ s ≤ t ∧ (t = s ∨ ∃ l ∈ ls, l.seq = t) ∧
      (∀ l ∈ ls, s < l.seq ∧ l.seq ≤ t) ∧
      (ls.map (·.seq)).Pairwise (· < ·) := by
  induction ls generalizing s c with
  | nil =>
    simp [replayFrom] at h
    obtain ⟨rfl, rfl⟩ := h
    simp
  | cons x xs ih =>
    simp only [replayFrom] at h
    split at h
    · rename_i hx
      obtain ⟨h1, h2, h3, h4, h5⟩ := ih h
      refine ⟨by simpa using h1, by omega, ?_, ?_, ?_⟩
      · rcases h3 with h3 | ⟨l, hl, hlt⟩
        · exact Or.inr ⟨x, by simp, h3.symm⟩
        · exact Or.inr ⟨l, by simp [hl], hlt⟩
      · intro l hl
        simp only [List.mem_cons] at hl
        rcases hl with rfl | hl
        · exact ⟨hx.1, h2⟩
        · have := h4 l hl; omega
      · simp only [List.map_cons, List.pairwise_cons, List.mem_map]
        refine ⟨?_, h5⟩
        rintro _ ⟨l, hl, rfl⟩
        exact (h4 l hl).1
    · simp at h

/-- The tree eventlog replays. -/
def Replays (log : List (Line D)) : Prop :=
  ∃ x, replayFrom H 0 init log = some x

theorem replays_nil : Replays H init ([] : List (Line D)) := ⟨_, rfl⟩

theorem replays_seq {log : List (Line D)} (h : Replays H init log) :
    (∀ l ∈ log, 0 < l.seq) ∧ (log.map (·.seq)).Pairwise (· < ·) := by
  obtain ⟨⟨t, r⟩, h⟩ := h
  have := replayFrom_some H h
  exact ⟨fun l hl => (this.2.2.2.1 l hl).1, this.2.2.2.2⟩

theorem replays_append {log : List (Line D)} {l : Line D}
    (h : Replays H init log)
    (hlt : ∀ x ∈ log, x.seq < l.seq) (hpos : 0 < l.seq)
    (hroot : l.root = H (rootOf H init log) l.digest) :
    Replays H init (log ++ [l]) := by
  obtain ⟨⟨t, r⟩, h⟩ := h
  obtain ⟨h1, -, h3, -, -⟩ := replayFrom_some H h
  have ht : t < l.seq := by
    rcases h3 with h3 | ⟨x, hx, rfl⟩
    · omega
    · exact hlt x hx
  refine ⟨(l.seq, H r l.digest), ?_⟩
  rw [replayFrom_append, h]
  have : l.root = H r l.digest := by rw [hroot, h1]; rfl
  simp [ht, this]

theorem replay_ok {log : List (Line D)} (h : Replays H init log)
    (hne : log ≠ []) :
    replay H init log = .ok (rootOf H init log) := by
  obtain ⟨⟨t, r⟩, h⟩ := h
  have h1 := (replayFrom_some H h).1
  cases log with
  | nil => exact absurd rfl hne
  | cons x xs =>
    simp only [replay, h, h1]
    rfl

end replay

section sync
variable [DecidableEq T] [DecidableEq M] [DecidableEq I] [DecidableEq D]
variable (H : D → D → D) (init : D)

/-- The state `cmd_bpm_tree_sync()` starts from when the node has none. -/
def fresh (t : T) : State T M D := ⟨t, 0, 0, init, none⟩

/-- `tree_recover_pending()`: the writes it makes and the state the loop
goes on from, or `none` for a refusal before it writes anything. Every
refusal after a write stops the run as a crash there does. -/
def recover (n : Node T M I D) (pub : Pub T M I D) (st : State T M D) :
    Option (List (Write T M I D) × State T M D) :=
  match n.pending with
  | none => some ([], st)
  | some p =>
    match pub.ops.find?
        (fun o => o.seq = p.seq ∧ o.id = p.id ∧ o.digest = p.digest) with
    | none => none
    | some o =>
      if p.seq ≤ st.lastSeq then some ([.unlink], st)
      else
        let next := H st.root p.digest
        let st' := { st with root := next, lastSeq := o.seq }
        let unapplied :=
          if (o.seq, o.digest) ∈ n.measured then
            some ([.append ⟨o.seq, o.digest, next⟩, .state st', .unlink], st')
          else some ([], st)
        match replay H init n.log with
        | .missing => unapplied
        | .bad => none
        | .ok r =>
          if r = next then some ([.state st', .unlink], st')
          else if r = st.root then unapplied
          else none

/-- The loop of `cmd_bpm_tree_sync()` over the operations, with `sel` what
`tree_selector_matches()` says of each: the writes and the state it ends
with. An operation at or below the cursor is passed over, one the selector
does not match moves the cursor, and one it does is applied. -/
def loop (sel : Op I D → Bool) :
    State T M D → List (Op I D) → List (Write T M I D) × State T M D
  | st, [] => ([], st)
  | st, o :: os =>
    if o.seq ≤ st.lastSeq then loop sel st os
    else if sel o then
      let st' := { st with root := H st.root o.digest, lastSeq := o.seq }
      let r := loop sel st' os
      ([.pending o, .measure o.seq o.digest,
        .append ⟨o.seq, o.digest, H st.root o.digest⟩, .state st',
        .unlink] ++ r.1,
        r.2)
    else loop sel { st with lastSeq := o.seq } os

/-- One `bpm tree sync` of the publication `pub`, fetched with the manifest
digest `m`, run to its end: the writes it makes, in order. -/
def run (n : Node T M I D) (pub : Pub T M I D) (m : M) (sel : Op I D → Bool) :
    List (Write T M I D) :=
  if Checked pub ∧ Follows pub n.state m then
    match recover H init n pub (n.state.getD (fresh init pub.treeId)) with
    | none => []
    | some (ws, st) =>
      let r := loop H sel st pub.ops
      let last := { r.2 with generation := pub.generation, manifest := some m }
      ws ++ r.1 ++ [.state last]
  else []

/-- What can happen to the node between two moments: a sync of a
publication the node verifies, stopped after any of its writes, or a
reboot, which starts this boot's records afresh. `Signed pub m` holds of a
publication signed by the key the node trusts, fetched with any manifest
digest `m` a registry wraps it in. -/
inductive Step (Signed : Pub T M I D → M → Prop) :
    Node T M I D → Node T M I D → Prop where
  | sync {n : Node T M I D} {pub : Pub T M I D} {m : M} (sel : Op I D → Bool)
      (k : Nat) : Signed pub m →
      Step Signed n (applyAll ((run H init n pub m sel).take k) n)
  | reboot {n : Node T M I D} : Step Signed n { n with measured := [] }

/-- Any number of steps. -/
inductive Steps (Signed : Pub T M I D → M → Prop) :
    Node T M I D → Node T M I D → Prop where
  | refl (n : Node T M I D) : Steps Signed n n
  | tail {n n' n'' : Node T M I D} :
      Steps Signed n n' → Step H init Signed n' n'' → Steps Signed n n''

end sync

/-! ### What every reachable node keeps -/

/-- The cursor the run starts from: the state's, 0 without one. -/
def cursor (n : Node T M I D) : Int :=
  match n.state with
  | some s => s.lastSeq
  | none => 0

/-- The `(seq, digest)` of each line, as a `tree_op` record holds them. -/
def events (log : List (Line D)) : List (Int × D) :=
  log.map fun l => (l.seq, l.digest)

/-- This boot's `tree_op` records are the last lines of the tree eventlog:
the operations applied since the boot began. -/
def Suffix (log : List (Line D)) (meas : List (Int × D)) : Prop :=
  ∃ L1 L2, log = L1 ++ L2 ∧ meas = events L2

/-- From `n` to `n'` nothing went back: the tree eventlog only grew, and the
state, once there, kept its tree, raised neither its generation nor its
cursor less than it had, and changed its manifest only with a later
generation. -/
structure Mono (n n' : Node T M I D) : Prop where
  log : ∃ L, n'.log = n.log ++ L
  state : ∀ s, n.state = some s → ∃ s', n'.state = some s' ∧
    s'.treeId = s.treeId ∧
    s.generation ≤ s'.generation ∧ s.lastSeq ≤ s'.lastSeq ∧
    (s'.generation = s.generation →
      s.manifest = none ∨ s'.manifest = s.manifest)

theorem Mono.refl (n : Node T M I D) : Mono n n :=
  ⟨⟨[], by simp⟩, fun s hs => ⟨s, hs, rfl, Int.le_refl _, Int.le_refl _,
    fun _ => Or.inr rfl⟩⟩

theorem Mono.trans {a b c : Node T M I D} (h1 : Mono a b) (h2 : Mono b c) :
    Mono a c := by
  refine ⟨?_, ?_⟩
  · obtain ⟨L, hL⟩ := h1.log
    obtain ⟨L', hL'⟩ := h2.log
    exact ⟨L ++ L', by rw [hL', hL, List.append_assoc]⟩
  · intro s hs
    obtain ⟨s', hs', ht, hg, hl, hm⟩ := h1.state s hs
    obtain ⟨s'', hs'', ht', hg', hl', hm'⟩ := h2.state s' hs'
    refine ⟨s'', hs'', ht'.trans ht, Int.le_trans hg hg', Int.le_trans hl hl',
      fun he => ?_⟩
    have e1 : s'.generation = s.generation := by omega
    have e2 : s''.generation = s'.generation := by omega
    rcases hm e1 with h | h
    · exact Or.inl h
    · rcases hm' e2 with h' | h'
      · rw [← h]; exact Or.inl h'
      · exact Or.inr (h'.trans h)

/-- A write that leaves the state alone and appends to the tree eventlog at
most. -/
theorem Mono.of_state {n n' : Node T M I D} (hs : n'.state = n.state)
    (hl : ∃ L, n'.log = n.log ++ L) : Mono n n' :=
  ⟨hl, fun s h => ⟨s, hs.trans h, rfl, Int.le_refl _, Int.le_refl _,
    fun _ => Or.inr rfl⟩⟩

section inv
variable [DecidableEq D] (H : D → D → D) (init : D)

/-- The projection root of the node's state, 64 zeros without one. -/
def rootAt (n : Node T M I D) : D :=
  match n.state with
  | some s => s.root
  | none => init

/-- The state is the fold of the tree eventlog, and its cursor at or past
every line of it. -/
def Clean (n : Node T M I D) : Prop :=
  rootAt init n = rootOf H init n.log ∧ ∀ l ∈ n.log, l.seq ≤ cursor n

/-- Where a run stopped, as far as the pending operation goes: the state
is the fold of the tree eventlog and this boot's records are its last
lines, with `pending.json` behind the cursor, or ahead of it and not yet
measured; or the pending operation is measured as well; or its line is
appended too, and the state not yet written. -/
def Window (n : Node T M I D) : Prop :=
  (Clean H init n ∧ Suffix n.log n.measured) ∨
  (∃ p, n.pending = some p ∧ cursor n < p.seq ∧ Clean H init n ∧
    ∃ L1 L2, n.log = L1 ++ L2 ∧ n.measured = events L2 ++ [(p.seq, p.digest)]) ∨
  (∃ p L0, n.pending = some p ∧ cursor n < p.seq ∧
    n.log = L0 ++ [⟨p.seq, p.digest, H (rootOf H init L0) p.digest⟩] ∧
    rootAt init n = rootOf H init L0 ∧ (∀ l ∈ L0, l.seq ≤ cursor n) ∧
    Suffix n.log n.measured)

/-- What every node a sync can leave holds: its tree eventlog replays, the
cursor is not negative, a recorded manifest is that of a signed
publication of the recorded generation, every line is an operation of a
signed publication of the recorded tree, without a state every line is
the pending operation's, and the window it stopped in. -/
structure Inv (Signed : Pub T M I D → M → Prop) (n : Node T M I D) : Prop where
  replays : Replays H init n.log
  cursor_nonneg : 0 ≤ cursor n
  bound : ∀ s m, n.state = some s → s.manifest = some m →
    ∃ p, Signed p m ∧ p.generation = s.generation
  applied : ∀ s, n.state = some s → ∀ l ∈ n.log, ∃ p m, Signed p m ∧
    p.treeId = s.treeId ∧ ∃ o ∈ p.ops, o.seq = l.seq ∧ o.digest = l.digest
  stateless : n.state = none → ∀ l ∈ n.log,
    ∃ p, n.pending = some p ∧ l.seq = p.seq ∧ l.digest = p.digest
  window : Window H init n

/-- Between two operations of the loop, the node `n` and the state `st`
the run holds: the node is clean, `st` its state with the cursor moved past
skipped operations, of the publication's tree, and recording `pub` with
`m` at the end goes forward. -/
structure LoopRel (Signed : Pub T M I D → M → Prop) (pub : Pub T M I D) (m : M)
    (n : Node T M I D) (st : State T M D) : Prop where
  replays : Replays H init n.log
  cursor_nonneg : 0 ≤ cursor n
  bound : ∀ s m, n.state = some s → s.manifest = some m →
    ∃ p, Signed p m ∧ p.generation = s.generation
  applied : ∀ s, n.state = some s → ∀ l ∈ n.log, ∃ p m, Signed p m ∧
    p.treeId = s.treeId ∧ ∃ o ∈ p.ops, o.seq = l.seq ∧ o.digest = l.digest
  clean : Clean H init n
  suffix : Suffix n.log n.measured
  root : st.root = rootAt init n
  le : cursor n ≤ st.lastSeq
  agree : ∀ s, n.state = some s →
    s.treeId = st.treeId ∧ s.generation = st.generation ∧
    s.manifest = st.manifest
  nolog : n.state = none → n.log = []
  tree : st.treeId = pub.treeId
  signed : Signed pub m
  gen : st.generation ≤ pub.generation ∧
    (pub.generation = st.generation → st.manifest = none ∨ st.manifest = some m)
  stBound : ∀ m', st.manifest = some m' →
    ∃ p, Signed p m' ∧ p.generation = st.generation

theorem LoopRel.inv {Signed : Pub T M I D → M → Prop}
    {pub : Pub T M I D} {m : M}
    {n : Node T M I D} {st : State T M D}
    (h : LoopRel H init Signed pub m n st) : Inv H init Signed n :=
  ⟨h.replays, h.cursor_nonneg, h.bound, h.applied,
    fun hs => by simp [h.nolog hs], Or.inl ⟨h.clean, h.suffix⟩⟩

theorem Inv.empty (Signed : Pub T M I D → M → Prop) :
    Inv H init Signed Node.empty :=
  ⟨replays_nil H init, by simp [cursor, Node.empty], by simp [Node.empty],
    by simp [Node.empty], by simp [Node.empty],
    Or.inl ⟨⟨by simp [rootAt, rootOf, Node.empty], by simp [Node.empty]⟩,
      [], [], by simp [Node.empty], by simp [Node.empty, events]⟩⟩

end inv

/-! ### A sync keeps the invariant and goes forward -/

section loop
variable [DecidableEq D] (H : D → D → D) (init : D)

/-- The state written after an operation's line, then `pending.json`
unlinked: the end of an applied operation, in the loop and in recovery. -/
theorem commit {Signed : Pub T M I D → M → Prop}
    {pub : Pub T M I D} {m : M}
    {n : Node T M I D} {st : State T M D} {o : Op I D} {L0 : List (Line D)}
    (hinv : Inv H init Signed n)
    (hlog : n.log = L0 ++ [⟨o.seq, o.digest, H st.root o.digest⟩])
    (hroot : st.root = rootOf H init L0) (hbelow : ∀ l ∈ L0, l.seq ≤ st.lastSeq)
    (hgt : st.lastSeq < o.seq) (hsuf : Suffix n.log n.measured)
    (happ : ∀ l ∈ n.log, ∃ p m, Signed p m ∧ p.treeId = st.treeId ∧
      ∃ o' ∈ p.ops, o'.seq = l.seq ∧ o'.digest = l.digest)
    (hle : cursor n ≤ st.lastSeq)
    (hagree : ∀ s, n.state = some s →
      s.treeId = st.treeId ∧ s.generation = st.generation ∧
      s.manifest = st.manifest)
    (htree : st.treeId = pub.treeId) (hsigned : Signed pub m)
    (hgen : st.generation ≤ pub.generation ∧
      (pub.generation = st.generation →
        st.manifest = none ∨ st.manifest = some m))
    (hstb : ∀ m', st.manifest = some m' →
      ∃ p, Signed p m' ∧ p.generation = st.generation) :
    Along (Inv H init Signed) Mono
      [.state ⟨st.treeId, st.generation, o.seq, H st.root o.digest,
          st.manifest⟩,
        .unlink] n ∧
      LoopRel H init Signed pub m
        (applyAll [.state ⟨st.treeId, st.generation, o.seq, H st.root o.digest,
          st.manifest⟩, .unlink] n)
        ⟨st.treeId, st.generation, o.seq, H st.root o.digest, st.manifest⟩ := by
  simp only [Along, applyAll, List.foldl, Write.apply]
  have hcur0 := hinv.cursor_nonneg
  have hclean : ∀ q, Clean H init (⟨some ⟨st.treeId, st.generation, o.seq,
      H st.root o.digest, st.manifest⟩, q, n.log, n.measured⟩ :
        Node T M I D) := by
    intro q
    refine ⟨?_, ?_⟩
    · show H st.root o.digest = _
      rw [hlog, rootOf_append, hroot]
    · intro l hl
      show l.seq ≤ o.seq
      rw [hlog] at hl
      rcases List.mem_append.1 hl with hl | hl
      · have := hbelow l hl; omega
      · simp only [List.mem_singleton] at hl; subst hl; exact Int.le_refl _
  have hmono' : ∀ q, Mono n (⟨some ⟨st.treeId, st.generation, o.seq,
      H st.root o.digest, st.manifest⟩, q, n.log, n.measured⟩ :
        Node T M I D) := by
    intro q
    refine ⟨⟨[], by simp⟩, fun s hs =>
      ⟨_, rfl, (hagree s hs).1.symm, ?_, ?_, fun _ => ?_⟩⟩
    · exact Int.le_of_eq (hagree s hs).2.1
    · have : cursor n = s.lastSeq := by simp [cursor, hs]
      show s.lastSeq ≤ o.seq
      omega
    · exact Or.inr (hagree s hs).2.2.symm
  have hinv' : ∀ q, Inv H init Signed (⟨some ⟨st.treeId, st.generation, o.seq,
      H st.root o.digest, st.manifest⟩, q, n.log, n.measured⟩ :
        Node T M I D) := by
    intro q
    refine ⟨hinv.replays, by show 0 ≤ o.seq; omega, ?_, ?_, by simp,
      Or.inl ⟨hclean q, hsuf⟩⟩
    · intro s m' hs hm
      simp only [Option.some.injEq] at hs
      subst hs
      exact hstb m' hm
    · intro s hs
      simp only [Option.some.injEq] at hs
      subst hs
      exact happ
  refine ⟨⟨hinv, hmono' _, hinv' _, Mono.of_state rfl ⟨[], by simp⟩,
    hinv' _⟩, ?_⟩
  obtain ⟨-, hc', hb', ha', -, -⟩ := hinv' none
  exact ⟨hinv.replays, hc', hb', ha', hclean none, hsuf, rfl, Int.le_refl _,
    fun s hs => by
      simp only [Option.some.injEq] at hs; subst hs; exact ⟨rfl, rfl, rfl⟩,
    by simp, htree, hsigned, hgen, hstb⟩

/-- One operation the loop applies, stopped after any of its writes. -/
theorem loop_apply {Signed : Pub T M I D → M → Prop}
    {pub : Pub T M I D} {m : M}
    {n : Node T M I D} {st : State T M D} {o : Op I D}
    (h : LoopRel H init Signed pub m n st) (hgt : st.lastSeq < o.seq)
    (ho : o ∈ pub.ops) :
    Along (Inv H init Signed) Mono
      [.pending o, .measure o.seq o.digest,
        .append ⟨o.seq, o.digest, H st.root o.digest⟩,
        .state { st with root := H st.root o.digest, lastSeq := o.seq },
        .unlink] n ∧
      LoopRel H init Signed pub m
        (applyAll [.pending o, .measure o.seq o.digest,
          .append ⟨o.seq, o.digest, H st.root o.digest⟩,
          .state { st with root := H st.root o.digest, lastSeq := o.seq },
          .unlink] n)
        { st with root := H st.root o.digest, lastSeq := o.seq } := by
  obtain ⟨hrep, hcur0, hbound, happ, ⟨hroot, hbelow⟩, ⟨L1, L2, hlog, hmeas⟩,
    hst, hle,
    hagree, hnolog, htree, hsigned, hgen, hstb⟩ := h
  have hlt : cursor n < o.seq := by omega
  have hpos : 0 < o.seq := by omega
  have hnext : H st.root o.digest = H (rootOf H init n.log) o.digest := by
    rw [hst, hroot]
  have hrep3 :
      Replays H init (n.log ++ [⟨o.seq, o.digest, H st.root o.digest⟩]) :=
    replays_append H init hrep
      (fun x hx => by have := hbelow x hx; show x.seq < o.seq; omega) hpos hnext
  have happ' : ∀ l ∈ n.log ++ [⟨o.seq, o.digest, H st.root o.digest⟩],
      ∃ p m, Signed p m ∧ p.treeId = st.treeId ∧
      ∃ o' ∈ p.ops, o'.seq = l.seq ∧ o'.digest = l.digest := by
    intro l hl
    rcases List.mem_append.1 hl with hl | hl
    · cases hs : n.state with
      | none => simp [hnolog hs] at hl
      | some s =>
        obtain ⟨p, m', h1, h2, h3⟩ := happ s hs l hl
        exact ⟨p, m', h1, h2.trans (hagree s hs).1, h3⟩
    · simp only [List.mem_singleton] at hl
      subst hl
      exact ⟨pub, m, hsigned, htree.symm, o, ho, rfl, rfl⟩
  have hsuf3 : Suffix (n.log ++ [⟨o.seq, o.digest, H st.root o.digest⟩])
      (n.measured ++ [(o.seq, o.digest)]) :=
    ⟨L1, L2 ++ [⟨o.seq, o.digest, H st.root o.digest⟩],
      by rw [hlog, List.append_assoc],
      by rw [hmeas]; simp [events]⟩
  have hinvn : Inv H init Signed n :=
    ⟨hrep, hcur0, hbound, happ, fun hs => by simp [hnolog hs],
      Or.inl ⟨⟨hroot, hbelow⟩, L1, L2, hlog, hmeas⟩⟩
  have hinv1 :
      Inv H init Signed (⟨n.state, some o, n.log, n.measured⟩ : Node T M I D) :=
    ⟨hrep, hcur0, hbound, happ, fun hs => by simp [hnolog hs],
      Or.inl ⟨⟨hroot, hbelow⟩, L1, L2, hlog, hmeas⟩⟩
  have hinv2 : Inv H init Signed (⟨n.state, some o, n.log,
      n.measured ++ [(o.seq, o.digest)]⟩ : Node T M I D) :=
    ⟨hrep, hcur0, hbound, happ, fun hs => by simp [hnolog hs],
      Or.inr (Or.inl ⟨o, rfl, hlt, ⟨hroot, hbelow⟩, L1, L2, hlog,
        by rw [hmeas]⟩)⟩
  have hinv3 : Inv H init Signed (⟨n.state, some o,
      n.log ++ [⟨o.seq, o.digest, H st.root o.digest⟩],
      n.measured ++ [(o.seq, o.digest)]⟩ : Node T M I D) := by
    refine ⟨hrep3, hcur0, hbound, fun s hs l hl => ?_, fun hs l hl => ?_,
      Or.inr (Or.inr ⟨o, n.log, rfl, hlt, by rw [hnext], hroot, hbelow, hsuf3⟩)⟩
    · obtain ⟨p, m', h1, h2, h3⟩ := happ' l hl
      exact ⟨p, m', h1, h2.trans (hagree s hs).1.symm, h3⟩
    · rw [hnolog hs] at hl
      simp only [List.nil_append, List.mem_singleton] at hl
      subst hl
      exact ⟨o, rfl, rfl, rfl⟩
  obtain ⟨hc, hr⟩ := commit H init (pub := pub) hinv3 rfl (hst.trans hroot)
    (fun l hl => by have := hbelow l hl; omega) hgt hsuf3 happ' hle hagree
    htree hsigned
    hgen hstb
  simp only [Along, applyAll, List.foldl, Write.apply] at hc hr ⊢
  exact ⟨⟨hinvn, Mono.of_state rfl ⟨[], by simp⟩, hinv1,
    Mono.of_state rfl ⟨[], by simp⟩,
    hinv2, Mono.of_state rfl ⟨_, rfl⟩, hc⟩, hr⟩

/-- An operation the selector does not match moves the cursor in memory. -/
theorem LoopRel.skip {Signed : Pub T M I D → M → Prop}
    {pub : Pub T M I D} {m : M}
    {n : Node T M I D} {st : State T M D} {s : Int}
    (h : LoopRel H init Signed pub m n st) (hs : st.lastSeq ≤ s) :
    LoopRel H init Signed pub m n { st with lastSeq := s } :=
  { h with le := Int.le_trans h.le hs }

/-- The loop, stopped after any of its writes. -/
theorem loop_inv {Signed : Pub T M I D → M → Prop}
    {pub : Pub T M I D} {m : M}
    (sel : Op I D → Bool) :
    ∀ (os : List (Op I D)) (n : Node T M I D) (st : State T M D),
      (∀ o ∈ os, o ∈ pub.ops) → LoopRel H init Signed pub m n st →
      Along (Inv H init Signed) Mono (loop H sel st os).1 n ∧
        LoopRel H init Signed pub m (applyAll (loop H sel st os).1 n)
          (loop H sel st os).2
  | [], _, _, _, h => ⟨h.inv, h⟩
  | o :: os, n, st, hsub, h => by
    have hsub' : ∀ o' ∈ os, o' ∈ pub.ops :=
      fun o' ho' => hsub o' (by simp [ho'])
    simp only [loop]
    split
    · exact loop_inv sel os n st hsub' h
    · rename_i hgt
      split
      · obtain ⟨ha, hr⟩ := loop_apply H init h (by omega) (hsub o (by simp))
        obtain ⟨ha', hr'⟩ := loop_inv sel os _ _ hsub' hr
        refine ⟨along_append ha ha', ?_⟩
        rw [applyAll_append]
        exact hr'
      · exact loop_inv sel os n _ hsub' (h.skip H init (by omega))

/-- The write that records the publication once the loop is done. -/
theorem final_write {Signed : Pub T M I D → M → Prop}
    {pub : Pub T M I D} {m : M}
    {n : Node T M I D} {st : State T M D}
    (h : LoopRel H init Signed pub m n st) :
    Inv H init Signed ((Write.state ⟨st.treeId, pub.generation, st.lastSeq,
        st.root,
        some m⟩).apply n) ∧
      Mono n ((Write.state ⟨st.treeId, pub.generation, st.lastSeq, st.root,
        some m⟩).apply n) := by
  obtain ⟨hrep, hcur0, -, happ, ⟨hroot, hbelow⟩, hsuf, hst, hle, hagree,
    hnolog, htree,
    hsigned, ⟨hgen, hgen'⟩, -⟩ := h
  simp only [Write.apply]
  refine ⟨⟨hrep, by show 0 ≤ st.lastSeq; omega, ?_, ?_, by simp,
    Or.inl ⟨⟨?_, ?_⟩, hsuf⟩⟩,
    ⟨[], by simp⟩, fun s hs => ⟨_, rfl, ?_, ?_, ?_, fun he => ?_⟩⟩
  · intro s m' hs hm
    simp only [Option.some.injEq] at hs
    subst hs
    simp only [Option.some.injEq] at hm
    subst hm
    exact ⟨pub, hsigned, rfl⟩
  · intro s hs l hl
    simp only [Option.some.injEq] at hs
    subst hs
    cases hs' : n.state with
    | none => simp [hnolog hs'] at hl
    | some s0 =>
      obtain ⟨p, m', h1, h2, h3⟩ := happ s0 hs' l hl
      exact ⟨p, m', h1, h2.trans (hagree s0 hs').1, h3⟩
  · show st.root = _
    rw [hst, hroot]
  · intro l hl
    show l.seq ≤ st.lastSeq
    have := hbelow l hl
    omega
  · exact (hagree s hs).1.symm
  · show s.generation ≤ pub.generation
    rw [(hagree s hs).2.1]
    exact hgen
  · have : cursor n = s.lastSeq := by simp [cursor, hs]
    show s.lastSeq ≤ st.lastSeq
    omega
  · have he' : pub.generation = st.generation := by
      rw [← (hagree s hs).2.1]; exact he
    rw [(hagree s hs).2.2]
    rcases hgen' he' with h0 | h0
    · exact Or.inl h0
    · exact Or.inr h0.symm

end loop

/-! ### Recovery and a whole run -/

section run
variable [DecidableEq T] [DecidableEq M] [DecidableEq I] [DecidableEq D]
variable (H : D → D → D) (init : D)

omit [DecidableEq I] in
/-- The state a run starts from, its own or a fresh one: it is the node's,
of the publication's tree, and recording `pub` with `m` at the end goes
forward. -/
theorem start_facts {Signed : Pub T M I D → M → Prop}
    {pub : Pub T M I D} {m : M}
    (hbind : ∀ p p' m, Signed p m → Signed p' m → p = p')
    {n : Node T M I D} (hinv : Inv H init Signed n)
    (hchk : Checked pub) (hfol : Follows pub n.state m) (hsig : Signed pub m) :
    (n.state.getD (fresh init pub.treeId)).root = rootAt init n ∧
      (n.state.getD (fresh init pub.treeId)).lastSeq = cursor n ∧
      (∀ s, n.state = some s →
        s.treeId = (n.state.getD (fresh init pub.treeId)).treeId ∧
        s.generation = (n.state.getD (fresh init pub.treeId)).generation ∧
        s.manifest = (n.state.getD (fresh init pub.treeId)).manifest) ∧
      (n.state.getD (fresh init pub.treeId)).treeId = pub.treeId ∧
      ((n.state.getD (fresh init pub.treeId)).generation ≤ pub.generation ∧
        (pub.generation = (n.state.getD (fresh init pub.treeId)).generation →
          (n.state.getD (fresh init pub.treeId)).manifest = none ∨
          (n.state.getD (fresh init pub.treeId)).manifest = some m)) ∧
      (∀ m', (n.state.getD (fresh init pub.treeId)).manifest = some m' →
        ∃ p, Signed p m' ∧
          p.generation =
            (n.state.getD (fresh init pub.treeId)).generation) := by
  cases hs : n.state with
  | none =>
    refine ⟨by simp [rootAt, fresh, hs], by simp [cursor, fresh, hs], by simp,
      by simp [fresh], ⟨by simpa [fresh] using hchk.1, fun _ => Or.inl rfl⟩,
      by simp [fresh]⟩
  | some s =>
    simp only [hs, Follows] at hfol
    refine ⟨by simp [rootAt, hs], by simp [cursor, hs], ?_, hfol.1, ?_,
      fun m' hm => hinv.bound s m' hs hm⟩
    · intro s' hs'
      simp only [Option.some.injEq] at hs'
      subst hs'
      exact ⟨rfl, rfl, rfl⟩
    · simp only [Option.getD_some]
      rcases hfol.2.1 with hm | hlt
      · obtain ⟨p0, hp0, hg⟩ := hinv.bound s m hs hm
        have := hbind _ _ _ hp0 hsig
        subst this
        exact ⟨Int.le_of_eq hg.symm, fun _ => Or.inr hm⟩
      · exact ⟨Int.le_of_lt hlt, fun he => absurd he (by omega)⟩

omit [DecidableEq T] [DecidableEq M] [DecidableEq I] in
/-- Without a state, a clean node has an empty tree eventlog. -/
theorem nolog_of_clean {Signed : Pub T M I D → M → Prop} {n : Node T M I D}
    (hinv : Inv H init Signed n) (hc : Clean H init n) (hs : n.state = none) :
    n.log = [] := by
  have h0 : cursor n = 0 := by simp [cursor, hs]
  have hpos := (replays_seq H init hinv.replays).1
  cases hl : n.log with
  | nil => rfl
  | cons l ls =>
    have h1 := hpos l (by simp [hl])
    have h2 := hc.2 l (by simp [hl])
    omega

omit [DecidableEq I] in
/-- A clean node goes on from the state it starts from. -/
theorem LoopRel.start {Signed : Pub T M I D → M → Prop}
    {pub : Pub T M I D} {m : M}
    (hbind : ∀ p p' m, Signed p m → Signed p' m → p = p')
    {n : Node T M I D} (hinv : Inv H init Signed n) (hclean : Clean H init n)
    (hsuf : Suffix n.log n.measured)
    (hchk : Checked pub) (hfol : Follows pub n.state m) (hsig : Signed pub m) :
    LoopRel H init Signed pub m n (n.state.getD (fresh init pub.treeId)) := by
  obtain ⟨hr, hc, ha, ht, hg, hb⟩ :=
    start_facts H init hbind hinv hchk hfol hsig
  exact ⟨hinv.replays, hinv.cursor_nonneg, hinv.bound, hinv.applied, hclean,
    hsuf, hr, Int.le_of_eq hc.symm, ha, nolog_of_clean H init hinv hclean, ht,
    hsig, hg, hb⟩

/-- What `tree_recover_pending()` writes, by where the run before it
stopped: nothing without a pending operation; the unlink alone when the
cursor is at or past it; nothing, leaving the cursor below it, when it is
neither measured nor appended; its line, the state and the unlink when it
is measured and not appended; and the state and the unlink when it is
appended. -/
def RecoverSpec (n : Node T M I D) (ws : List (Write T M I D))
    (st : State T M D) : Prop :=
  match n.pending with
  | none => ws = []
  | some p =>
    (p.seq ≤ cursor n ∧ ws = [.unlink]) ∨
    (cursor n < p.seq ∧ (p.seq, p.digest) ∉ n.measured ∧
      (p.seq, p.digest) ∉ events n.log ∧
      ws = [] ∧ st.lastSeq = cursor n) ∨
    (cursor n < p.seq ∧ (p.seq, p.digest) ∈ n.measured ∧
      (p.seq, p.digest) ∉ events n.log ∧
      (∃ r, ws = [.append ⟨p.seq, p.digest, r⟩, .state st, .unlink]) ∧
      st.lastSeq = p.seq) ∨
    (cursor n < p.seq ∧ (p.seq, p.digest) ∈ events n.log ∧
      ws = [.state st, .unlink] ∧
      st.lastSeq = p.seq)

/-- `tree_recover_pending()`, stopped after any of its writes: every node
it leaves keeps the invariant and goes forward, the loop goes on from a
clean node, and it writes what `RecoverSpec` says. -/
theorem recover_inv {Signed : Pub T M I D → M → Prop}
    (hbind : ∀ p p' m, Signed p m → Signed p' m → p = p')
    (hH : ∀ a b c d, H a b = H c d → a = c ∧ b = d)
    (hinit : ∀ a b, H a b ≠ init)
    {n : Node T M I D} {pub : Pub T M I D} {m : M} (hinv : Inv H init Signed n)
    (hchk : Checked pub) (hfol : Follows pub n.state m) (hsig : Signed pub m)
    {ws : List (Write T M I D)} {st : State T M D}
    (hrec : recover H init n pub (n.state.getD (fresh init pub.treeId)) =
      some (ws, st)) :
    Along (Inv H init Signed) Mono ws n ∧
      LoopRel H init Signed pub m (applyAll ws n) st ∧ RecoverSpec n ws st := by
  obtain ⟨hst0r, hst0c, hagree, htree, hgen, hstb⟩ :=
    start_facts H init hbind hinv hchk hfol hsig
  have hgo : Clean H init n → Suffix n.log n.measured →
      LoopRel H init Signed pub m n (n.state.getD (fresh init pub.treeId)) :=
    fun hc hs => LoopRel.start H init hbind hinv hc hs hchk hfol hsig
  -- What the tree eventlog replays to on a clean node.
  have hrepl : Clean H init n →
      replay H init n.log = .missing ∨
      replay H init n.log = .ok (rootAt init n) := by
    intro hc
    cases hl : n.log with
    | nil => exact Or.inl rfl
    | cons l ls =>
      right
      rw [← hl, replay_ok H init hinv.replays (by simp [hl]), hc.1]
  unfold recover at hrec
  cases hp : n.pending with
  | none =>
    simp only [hp, Option.some.injEq, Prod.mk.injEq] at hrec
    obtain ⟨rfl, rfl⟩ := hrec
    have hw : Clean H init n ∧ Suffix n.log n.measured := by
      rcases hinv.window with h | ⟨p, hp', _⟩ | ⟨p, _, hp', _⟩
      · exact h
      · simp [hp] at hp'
      · simp [hp] at hp'
    exact ⟨hinv, hgo hw.1 hw.2, by simp [RecoverSpec, hp]⟩
  | some p =>
    simp only [hp] at hrec
    split at hrec
    · simp at hrec
    rename_i o hf
    have ho : o ∈ pub.ops := List.mem_of_find?_eq_some hf
    have hos := List.find?_some hf
    simp only [decide_eq_true_eq] at hos
    have hop : o = p := by
      obtain ⟨h1, h2, h3⟩ := hos
      cases o
      cases p
      simp only at h1 h2 h3
      subst h1 h2 h3
      rfl
    subst hop
    split at hrec
    · rename_i hle
      simp only [Option.some.injEq, Prod.mk.injEq] at hrec
      obtain ⟨rfl, rfl⟩ := hrec
      have hw : Clean H init n ∧ Suffix n.log n.measured := by
        rcases hinv.window with h | ⟨p', hp', hlt, _⟩ | ⟨p', _, hp', hlt, _⟩
        · exact h
        · rw [hp, Option.some.injEq] at hp'; subst hp'; omega
        · rw [hp, Option.some.injEq] at hp'; subst hp'; omega
      have hinv' : Inv H init Signed
          (⟨n.state, none, n.log, n.measured⟩ : Node T M I D) :=
        ⟨hinv.replays, hinv.cursor_nonneg, hinv.bound, hinv.applied,
          fun hs => by simp [nolog_of_clean H init hinv hw.1 hs], Or.inl hw⟩
      have hspec :
          RecoverSpec n [.unlink] (n.state.getD (fresh init pub.treeId)) := by
        simp only [RecoverSpec, hp]
        exact Or.inl ⟨by omega, trivial⟩
      simp only [Along, applyAll, List.foldl, Write.apply]
      exact ⟨⟨hinv, Mono.of_state rfl ⟨[], by simp⟩, hinv'⟩,
        LoopRel.start H init (n := ⟨n.state, none, n.log, n.measured⟩) hbind
          hinv' hw.1 hw.2
          hchk hfol hsig, hspec⟩
    rename_i hgt
    have hlt : cursor n < o.seq := by omega
    -- The pending operation has no line at or below the cursor.
    have hnotin : ∀ L : List (Line D), (∀ l ∈ L, l.seq ≤ cursor n) →
        (o.seq, o.digest) ∉ events L := by
      intro L hL hin
      simp only [events, List.mem_map, Prod.mk.injEq] at hin
      obtain ⟨l, hl, hs, -⟩ := hin
      have := hL l hl
      omega
    rcases hinv.window with ⟨hc, hsuf⟩ | ⟨p', hp', -, hc, L1, L2, hlog, hmeas⟩ |
        ⟨p', L0, hp', -, hlog, hroot, hbelow, hsuf⟩
    · -- Clean, the operation not measured: the loop retries it.
      have hnm : (o.seq, o.digest) ∉ n.measured := by
        obtain ⟨L1, L2, hlog, hmeas⟩ := hsuf
        rw [hmeas]
        exact hnotin L2 (fun l hl =>
          hc.2 l (by rw [hlog]; exact List.mem_append_right _ hl))
      have hne : rootAt init n ≠
          H (n.state.getD (fresh init pub.treeId)).root o.digest := by
        rw [hst0r, hc.1]; exact rootOf_ne_next H init hH hinit _ _
      rcases hrepl hc with h | h <;> rw [h] at hrec <;> simp only at hrec
      · rw [ite_eq_right hnm] at hrec
        simp only [Option.some.injEq, Prod.mk.injEq] at hrec
        obtain ⟨rfl, rfl⟩ := hrec
        refine ⟨hinv, hgo hc hsuf, ?_⟩
        simp only [RecoverSpec, hp]
        exact Or.inr (Or.inl ⟨hlt, hnm, hnotin n.log hc.2, trivial, hst0c⟩)
      · rw [ite_eq_right hne, ite_eq_left hst0r.symm, ite_eq_right hnm] at hrec
        simp only [Option.some.injEq, Prod.mk.injEq] at hrec
        obtain ⟨rfl, rfl⟩ := hrec
        refine ⟨hinv, hgo hc hsuf, ?_⟩
        simp only [RecoverSpec, hp]
        exact Or.inr (Or.inl ⟨hlt, hnm, hnotin n.log hc.2, trivial, hst0c⟩)
    · -- Measured, its line not appended: append it, then commit.
      rw [hp, Option.some.injEq] at hp'
      subst hp'
      have hm : (o.seq, o.digest) ∈ n.measured := by rw [hmeas]; simp
      have hne : rootAt init n ≠
          H (n.state.getD (fresh init pub.treeId)).root o.digest := by
        rw [hst0r, hc.1]; exact rootOf_ne_next H init hH hinit _ _
      have hroot0 :
          (n.state.getD (fresh init pub.treeId)).root = rootOf H init n.log :=
        hst0r.trans hc.1
      have hrep1 : Replays H init (n.log ++ [⟨o.seq, o.digest,
          H (n.state.getD (fresh init pub.treeId)).root o.digest⟩]) :=
        replays_append H init hinv.replays
          (fun x hx => by have := hc.2 x hx; show x.seq < o.seq; omega) (by
            have := hinv.cursor_nonneg; show 0 < o.seq; omega) (by rw [hroot0])
      have hnolog := nolog_of_clean H init hinv hc
      have happ1 : ∀ l ∈ n.log ++ [⟨o.seq, o.digest,
          H (n.state.getD (fresh init pub.treeId)).root o.digest⟩],
          ∃ q m', Signed q m' ∧
          q.treeId = (n.state.getD (fresh init pub.treeId)).treeId ∧
          ∃ o' ∈ q.ops, o'.seq = l.seq ∧ o'.digest = l.digest := by
        intro l hl
        rcases List.mem_append.1 hl with hl | hl
        · rcases Option.eq_none_or_eq_some n.state with hs | ⟨s, hs⟩
          · simp [hnolog hs] at hl
          · obtain ⟨q, m', h1, h2, h3⟩ := hinv.applied s hs l hl
            exact ⟨q, m', h1, h2.trans (hagree s hs).1, h3⟩
        · simp only [List.mem_singleton] at hl
          subst hl
          exact ⟨pub, m, hsig, htree.symm, o, ho, rfl, rfl⟩
      have hinv1 : Inv H init Signed (⟨n.state, n.pending,
          n.log ++ [⟨o.seq, o.digest,
          H (n.state.getD (fresh init pub.treeId)).root o.digest⟩],
          n.measured⟩ :
          Node T M I D) := by
        refine ⟨hrep1, hinv.cursor_nonneg, hinv.bound, fun s hs l hl => ?_,
          fun hs l hl => ?_, Or.inr (Or.inr ⟨o, n.log, hp, hlt,
            by rw [hroot0], hc.1, hc.2,
            L1, L2 ++ [_], by rw [hlog, List.append_assoc],
            by rw [hmeas]; simp [events]⟩)⟩
        · obtain ⟨q, m', h1, h2, h3⟩ := happ1 l hl
          exact ⟨q, m', h1, h2.trans (hagree s hs).1.symm, h3⟩
        · rw [hnolog hs] at hl
          simp only [List.nil_append, List.mem_singleton] at hl
          subst hl
          exact ⟨o, hp, rfl, rfl⟩
      rcases hrepl hc with h | h <;> rw [h] at hrec <;> simp only at hrec
      all_goals first
        | rw [ite_eq_right hne, ite_eq_left hst0r.symm, ite_eq_left hm] at hrec
        | rw [ite_eq_left hm] at hrec
      all_goals
        simp only [Option.some.injEq, Prod.mk.injEq] at hrec
        obtain ⟨rfl, rfl⟩ := hrec
        obtain ⟨hca, hcr⟩ :=
          commit H init (pub := pub) (L0 := n.log) hinv1 rfl hroot0
          (fun l hl => by have := hc.2 l hl; omega) (by omega)
          ⟨L1, L2 ++ [_], by rw [hlog, List.append_assoc],
            by rw [hmeas]; simp [events]⟩
          happ1 (Int.le_of_eq hst0c.symm) hagree htree hsig hgen hstb
        refine ⟨⟨hinv, Mono.of_state rfl ⟨_, rfl⟩, hca⟩, hcr, ?_⟩
        simp only [RecoverSpec, hp]
        exact Or.inr (Or.inr (Or.inl
          ⟨hlt, hm, hnotin n.log hc.2, ⟨_, rfl⟩, trivial⟩))
    · -- Its line appended too: commit.
      rw [hp, Option.some.injEq] at hp'
      subst hp'
      have hroot0 :
          (n.state.getD (fresh init pub.treeId)).root = rootOf H init L0 :=
        hst0r.trans hroot
      have hok : replay H init n.log =
          .ok (H (n.state.getD (fresh init pub.treeId)).root o.digest) := by
        rw [replay_ok H init hinv.replays (by simp [hlog]), hlog,
          rootOf_append, hroot0]
      rw [hok] at hrec
      simp only [ite_true, Option.some.injEq, Prod.mk.injEq] at hrec
      obtain ⟨rfl, rfl⟩ := hrec
      have happ0 : ∀ l ∈ n.log, ∃ q m', Signed q m' ∧
          q.treeId = (n.state.getD (fresh init pub.treeId)).treeId ∧
          ∃ o' ∈ q.ops, o'.seq = l.seq ∧ o'.digest = l.digest := by
        intro l hl
        rcases Option.eq_none_or_eq_some n.state with hs | ⟨s, hs⟩
        · obtain ⟨q, hq, h1, h2⟩ := hinv.stateless hs l hl
          rw [hp, Option.some.injEq] at hq
          subst hq
          exact ⟨pub, m, hsig, htree.symm, _, ho, h1.symm, h2.symm⟩
        · obtain ⟨q, m', h1, h2, h3⟩ := hinv.applied s hs l hl
          exact ⟨q, m', h1, h2.trans (hagree s hs).1, h3⟩
      obtain ⟨hca, hcr⟩ := commit H init (pub := pub) (L0 := L0) hinv
        (by rw [hlog, hroot0]) hroot0
        (fun l hl => by have := hbelow l hl; omega) (by omega) hsuf happ0
        (Int.le_of_eq hst0c.symm) hagree htree hsig hgen hstb
      refine ⟨hca, hcr, ?_⟩
      simp only [RecoverSpec, hp]
      exact Or.inr (Or.inr (Or.inr
        ⟨hlt, by rw [hlog]; simp [events], trivial, trivial⟩))

/-- What the theorems assume and the C cannot show. A manifest digest
names one publication: it is the SHA-256 of the manifest, and
`bpm_oci_get_signed()` takes the one payload layer the manifest names by
its SHA-256 and checks it, while a registry may wrap one publication in any
number of manifests. And the projection hash is collision resistant,
modelled as `Shirudo.Chain` models it: injective on (root, digest) pairs
and never the 64 zeros. -/
structure Assumptions (H : D → D → D) (init : D)
    (Signed : Pub T M I D → M → Prop) : Prop where
  binds : ∀ p p' m, Signed p m → Signed p' m → p = p'
  hash_inj : ∀ a b c d, H a b = H c d → a = c ∧ b = d
  hash_init : ∀ a b, H a b ≠ init

/-- A whole sync, stopped after any of its writes. -/
theorem run_inv {Signed : Pub T M I D → M → Prop}
    (ha : Assumptions H init Signed)
    {n : Node T M I D} {pub : Pub T M I D} {m : M} (sel : Op I D → Bool)
    (hinv : Inv H init Signed n) (hsig : Signed pub m) :
    Along (Inv H init Signed) Mono (run H init n pub m sel) n := by
  unfold run
  split
  · rename_i hc
    obtain ⟨hchk, hfol⟩ := hc
    split
    · exact hinv
    · rename_i ws st hrec
      obtain ⟨hw, hr, -⟩ := recover_inv H init ha.binds ha.hash_inj
        ha.hash_init hinv hchk
        hfol hsig hrec
      obtain ⟨hl, hr'⟩ := loop_inv H init sel pub.ops _ _ (fun _ ho => ho) hr
      refine along_append (along_append hw hl) ?_
      rw [applyAll_append]
      obtain ⟨hfi, hfm⟩ := final_write H init hr'
      exact ⟨hr'.inv, hfm, hfi⟩
  · exact hinv

/-- One step keeps the invariant and goes forward. -/
theorem step_inv {Signed : Pub T M I D → M → Prop}
    (ha : Assumptions H init Signed)
    {n n' : Node T M I D} (hinv : Inv H init Signed n)
    (h : Step H init Signed n n') :
    Inv H init Signed n' ∧ Mono n n' := by
  cases h with
  | sync sel k hsig =>
    have h := run_inv H init ha sel hinv hsig
    exact ⟨along_take h k,
      along_between Mono.refl (fun _ _ _ => Mono.trans) h 0 k
      (Nat.zero_le _)⟩
  | reboot =>
    refine ⟨⟨hinv.replays, hinv.cursor_nonneg, hinv.bound, hinv.applied,
      hinv.stateless,
      ?_⟩, Mono.of_state rfl ⟨[], by simp⟩⟩
    rcases hinv.window with ⟨hc, -⟩ | ⟨p, hp, -, hc, -⟩ |
        ⟨p, L0, hp, hlt, hlog, hroot, hbelow, -⟩
    · exact Or.inl ⟨hc, n.log, [], by simp, rfl⟩
    · exact Or.inl ⟨hc, n.log, [], by simp, rfl⟩
    · exact Or.inr (Or.inr
        ⟨p, L0, hp, hlt, hlog, hroot, hbelow, n.log, [], by simp, rfl⟩)

theorem Steps.trans {Signed : Pub T M I D → M → Prop} {a b c : Node T M I D}
    (h1 : Steps H init Signed a b) (h2 : Steps H init Signed b c) :
    Steps H init Signed a c := by
  induction h2 with
  | refl => exact h1
  | tail _ hs ih => exact Steps.tail ih hs

theorem steps_inv {Signed : Pub T M I D → M → Prop}
    (ha : Assumptions H init Signed)
    {n n' : Node T M I D} (hinv : Inv H init Signed n)
    (h : Steps H init Signed n n') :
    Inv H init Signed n' ∧ Mono n n' := by
  induction h with
  | refl => exact ⟨hinv, Mono.refl _⟩
  | tail _ hs ih =>
    obtain ⟨hi, hm⟩ := ih
    obtain ⟨hi', hm'⟩ := step_inv H init ha hi hs
    exact ⟨hi', hm.trans hm'⟩

/-- A node some sequence of syncs, crashes and reboots leaves, from before
its first sync. -/
def Reach (Signed : Pub T M I D → M → Prop) (n : Node T M I D) : Prop :=
  Steps H init Signed Node.empty n

/-- Every node a sequence of syncs, crashes and reboots leaves keeps the
invariant. -/
theorem reach_inv {Signed : Pub T M I D → M → Prop}
    (ha : Assumptions H init Signed)
    {n : Node T M I D} (h : Reach H init Signed n) : Inv H init Signed n :=
  (steps_inv H init ha (Inv.empty H init Signed) h).1

/-- Two points of the node's history in order: any number of steps
apart, two points of one sync where a crash could stop it, or a chain of
those. It orders every two nodes a sequence of syncs, crashes and reboots
passes through, those a sync passes on its way included. -/
inductive Later (Signed : Pub T M I D → M → Prop) :
    Node T M I D → Node T M I D → Prop where
  | steps {n n' : Node T M I D} : Steps H init Signed n n' → Later Signed n n'
  | within {n0 : Node T M I D} {pub : Pub T M I D} {m : M} (sel : Op I D → Bool)
      {i j : Nat} : Reach H init Signed n0 → Signed pub m → i ≤ j →
      Later Signed (applyAll ((run H init n0 pub m sel).take i) n0)
        (applyAll ((run H init n0 pub m sel).take j) n0)
  | trans {a b c : Node T M I D} :
      Later Signed a b → Later Signed b c → Later Signed a c

theorem later_reach {Signed : Pub T M I D → M → Prop} {n n' : Node T M I D}
    (hr : Reach H init Signed n) (h : Later H init Signed n n') :
    Reach H init Signed n' := by
  induction h with
  | steps hs => exact hr.trans H init hs
  | within sel h0 hsig _ => exact Steps.tail h0 (Step.sync sel _ hsig)
  | trans _ _ ih1 ih2 => exact ih2 (ih1 hr)

/-- Every later point of the node's history keeps the invariant and is
forward of an earlier one. -/
theorem later_mono {Signed : Pub T M I D → M → Prop}
    (ha : Assumptions H init Signed)
    {n n' : Node T M I D} (hr : Reach H init Signed n)
    (h : Later H init Signed n n') :
    Mono n n' := by
  induction h with
  | steps hs => exact (steps_inv H init ha (reach_inv H init ha hr) hs).2
  | within sel h0 hsig hij =>
    exact along_between Mono.refl (fun _ _ _ => Mono.trans)
      (run_inv H init ha sel (reach_inv H init ha h0) hsig) _ _ hij
  | trans h1 _ ih1 ih2 => exact (ih1 hr).trans (ih2 (later_reach H init hr h1))

/-! ### The node never goes back -/

/-- The generation never decreases, between any two points of any
sequence of syncs of any signed publications, crashes and reboots. -/
theorem generation_mono {Signed : Pub T M I D → M → Prop}
    (ha : Assumptions H init Signed)
    {n n' : Node T M I D} (hr : Reach H init Signed n)
    (hs : Later H init Signed n n')
    {s : State T M D} (hst : n.state = some s) :
    ∃ s', n'.state = some s' ∧ s'.treeId = s.treeId ∧
      s.generation ≤ s'.generation := by
  obtain ⟨s', h1, h2, h3, -⟩ := (later_mono H init ha hr hs).state s hst
  exact ⟨s', h1, h2, h3⟩

/-- At an equal generation the node only ever holds the manifest it
recorded, at any later point of its history. -/
theorem manifest_fixed {Signed : Pub T M I D → M → Prop}
    (ha : Assumptions H init Signed)
    {n n' : Node T M I D} (hr : Reach H init Signed n)
    (hs : Later H init Signed n n')
    {s s' : State T M D} {mf : M} (hst : n.state = some s)
    (hm : s.manifest = some mf)
    (hst' : n'.state = some s') (hg : s'.generation = s.generation) :
    s'.manifest = some mf := by
  obtain ⟨s'', h1, -, -, -, h5⟩ := (later_mono H init ha hr hs).state s hst
  rw [hst', Option.some.injEq] at h1
  subst h1
  rcases h5 hg with h | h
  · rw [hm] at h; cases h
  · rw [h, hm]

/-- The cursor never decreases, between any two points of the node's
history. -/
theorem lastSeq_mono {Signed : Pub T M I D → M → Prop}
    (ha : Assumptions H init Signed)
    {n n' : Node T M I D} (hr : Reach H init Signed n)
    (hs : Later H init Signed n n')
    {s : State T M D} (hst : n.state = some s) :
    ∃ s', n'.state = some s' ∧ s.lastSeq ≤ s'.lastSeq := by
  obtain ⟨s', h1, -, -, h4, -⟩ := (later_mono H init ha hr hs).state s hst
  exact ⟨s', h1, h4⟩

/-- `Follows` refuses a publication of an earlier generation than the
node's, or of its generation in another manifest, so a sync of it writes
nothing. -/
theorem older_refused {Signed : Pub T M I D → M → Prop}
    (ha : Assumptions H init Signed)
    {n : Node T M I D} (hr : Reach H init Signed n) {s : State T M D}
    (hst : n.state = some s) {q : Pub T M I D} {mq : M} (hq : Signed q mq)
    (hold : q.generation < s.generation ∨
      (q.generation = s.generation ∧ s.manifest ≠ some mq))
    (sel : Op I D → Bool) :
    run H init n q mq sel = [] := by
  have hinv := reach_inv H init ha hr
  unfold run
  rw [ite_eq_right]
  rintro ⟨-, hfol⟩
  rw [hst] at hfol
  obtain ⟨-, hgen, -⟩ := hfol
  rcases hgen with hm | hlt
  · obtain ⟨p0, hp0, hg⟩ := hinv.bound s mq hst hm
    have := ha.binds _ _ _ hp0 hq
    subst this
    rcases hold with h | ⟨-, h⟩
    · omega
    · exact h hm
  · rcases hold with h | ⟨h, -⟩ <;> omega

/-- Once the node has accepted a publication, recording its manifest,
every later sync of a publication of an earlier generation writes
nothing. -/
theorem accepted_older_refused {Signed : Pub T M I D → M → Prop}
    (ha : Assumptions H init Signed)
    {n n' : Node T M I D} (hr : Reach H init Signed n)
    (hs : Later H init Signed n n')
    {s : State T M D} {p : Pub T M I D} {mp : M} (hst : n.state = some s)
    (hm : s.manifest = some mp) (hp : Signed p mp)
    {q : Pub T M I D} {mq : M} (hq : Signed q mq)
    (hold : q.generation < p.generation)
    (sel : Op I D → Bool) :
    run H init n' q mq sel = [] := by
  have hinv := reach_inv H init ha hr
  obtain ⟨p0, hp0, hg⟩ := hinv.bound s mp hst hm
  have := ha.binds _ _ _ hp0 hp
  subst this
  obtain ⟨s', hs', -, hge⟩ := generation_mono H init ha hr hs hst
  exact older_refused H init ha (later_reach H init hr hs) hs' hq
    (Or.inl (by omega)) sel

/-! ### Each operation once, in order, and the state its fold -/

/-- The tree eventlog holds each operation at most once, in increasing
order of sequence number. -/
theorem log_increasing {Signed : Pub T M I D → M → Prop}
    (ha : Assumptions H init Signed)
    {n : Node T M I D} (hr : Reach H init Signed n) :
    (n.log.map (·.seq)).Pairwise (· < ·) ∧ ∀ l ∈ n.log, 0 < l.seq :=
  let h := replays_seq H init (reach_inv H init ha hr).replays
  ⟨h.2, h.1⟩

/-- The tree eventlog only grows: with `log_increasing`, an operation is
applied at most once over the node's whole history. -/
theorem log_grows {Signed : Pub T M I D → M → Prop}
    (ha : Assumptions H init Signed)
    {n n' : Node T M I D} (hr : Reach H init Signed n)
    (hs : Later H init Signed n n') :
    ∃ L, n'.log = n.log ++ L :=
  (later_mono H init ha hr hs).log

omit [DecidableEq T] [DecidableEq M] [DecidableEq I] [DecidableEq D] in
theorem suffix_pairwise {log L2 : List (Line D)} {L1 : List (Line D)}
    (hlog : log = L1 ++ L2) (h : (log.map (·.seq)).Pairwise (· < ·)) :
    ((events L2).map Prod.fst).Pairwise (· < ·) := by
  rw [hlog, List.map_append, List.pairwise_append] at h
  simpa [events, List.map_map, Function.comp_def] using h.2.1

/-- This boot's eventlog measures each operation at most once, in
increasing order. -/
theorem measured_increasing {Signed : Pub T M I D → M → Prop}
    (ha : Assumptions H init Signed)
    {n : Node T M I D} (hr : Reach H init Signed n) :
    (n.measured.map Prod.fst).Pairwise (· < ·) := by
  have hinv := reach_inv H init ha hr
  have hlog := (replays_seq H init hinv.replays).2
  rcases hinv.window with ⟨-, L1, L2, hl, hm⟩ |
      ⟨p, -, hlt, hc, L1, L2, hl, hm⟩ |
      ⟨-, -, -, -, -, -, -, L1, L2, hl, hm⟩
  · rw [hm]; exact suffix_pairwise hl hlog
  · rw [hm, List.map_append, List.pairwise_append]
    refine ⟨suffix_pairwise hl hlog, by simp, ?_⟩
    intro a ha b hb
    simp only [events, List.map_map, List.mem_map, Function.comp_def] at ha
    obtain ⟨l, hl2, rfl⟩ := ha
    simp only [List.map_cons, List.map_nil, List.mem_singleton] at hb
    subst hb
    have := hc.2 l (by rw [hl]; exact List.mem_append_right _ hl2)
    show l.seq < p.seq
    omega
  · rw [hm]; exact suffix_pairwise hl hlog

/-- Nothing measured is lost: every operation this boot measured has its
line in the tree eventlog, or is the pending one, still ahead of the
cursor, which the next recovery completes. -/
theorem measured_kept {Signed : Pub T M I D → M → Prop}
    (ha : Assumptions H init Signed)
    {n : Node T M I D} (hr : Reach H init Signed n) :
    ∀ e ∈ n.measured, e ∈ events n.log ∨
      ∃ p, n.pending = some p ∧ e = (p.seq, p.digest) ∧ cursor n < p.seq := by
  have hinv := reach_inv H init ha hr
  have hsub : ∀ {L1 L2 : List (Line D)} {e}, n.log = L1 ++ L2 → e ∈ events L2 →
      e ∈ events n.log := by
    intro L1 L2 e hl he
    rw [hl, events, List.map_append]
    exact List.mem_append_right _ he
  intro e he
  rcases hinv.window with ⟨-, L1, L2, hl, hm⟩ |
      ⟨p, hp, hlt, -, L1, L2, hl, hm⟩ |
      ⟨-, -, -, -, -, -, -, L1, L2, hl, hm⟩
  · rw [hm] at he; exact Or.inl (hsub hl he)
  · rw [hm, List.mem_append] at he
    rcases he with he | he
    · exact Or.inl (hsub hl he)
    · simp only [List.mem_singleton] at he
      exact Or.inr ⟨p, hp, he, hlt⟩
  · rw [hm] at he; exact Or.inl (hsub hl he)

/-- A crash between writing `pending.json` and committing the state: the
recovery of the next sync appends the pending operation's line exactly
when this boot measured it or its line is there already, appends at most
that one line, and otherwise leaves the cursor below the operation, so the
loop applies it; afterwards everything measured is in the tree eventlog. -/
theorem recover_pending {Signed : Pub T M I D → M → Prop}
    (ha : Assumptions H init Signed)
    {n : Node T M I D} (hr : Reach H init Signed n) {pub : Pub T M I D} {m : M}
    (hchk : Checked pub) (hfol : Follows pub n.state m) (hsig : Signed pub m)
    {p : Op I D} (hp : n.pending = some p) (hlt : cursor n < p.seq)
    {ws : List (Write T M I D)} {st : State T M D}
    (hrec : recover H init n pub (n.state.getD (fresh init pub.treeId)) =
      some (ws, st)) :
    (∃ L, (applyAll ws n).log = n.log ++ L ∧ L.length ≤ 1) ∧
      ((p.seq, p.digest) ∈ events (applyAll ws n).log ↔
        (p.seq, p.digest) ∈ n.measured ∨ (p.seq, p.digest) ∈ events n.log) ∧
      ((p.seq, p.digest) ∉ events (applyAll ws n).log → st.lastSeq < p.seq) ∧
      ∀ e ∈ (applyAll ws n).measured, e ∈ events (applyAll ws n).log := by
  have hinv := reach_inv H init ha hr
  obtain ⟨-, hrel, hspec⟩ :=
    recover_inv H init ha.binds ha.hash_inj ha.hash_init hinv hchk hfol hsig
      hrec
  have hkept :
      ∀ e ∈ (applyAll ws n).measured, e ∈ events (applyAll ws n).log := by
    obtain ⟨L1, L2, hl, hm⟩ := hrel.suffix
    intro e he
    rw [hm] at he
    rw [hl, events, List.map_append]
    exact List.mem_append_right _ he
  simp only [RecoverSpec, hp] at hspec
  rcases hspec with ⟨hle, -⟩ | ⟨-, hnm, hnl, rfl, hst⟩ |
      ⟨-, hm, hnl, ⟨r, rfl⟩, -⟩ |
      ⟨-, hl, rfl, -⟩
  · omega
  · exact ⟨⟨[], by simp [applyAll], by simp⟩,
      ⟨fun h => Or.inr h, fun h => h.elim (fun h' => absurd h' hnm) id⟩,
      fun _ => by omega, hkept⟩
  · have hin :
        (p.seq, p.digest) ∈ events (n.log ++ [⟨p.seq, p.digest, r⟩]) := by
      simp [events]
    exact ⟨⟨_, rfl, by simp⟩, ⟨fun _ => Or.inl hm, fun _ => hin⟩,
      fun h => absurd hin h, hkept⟩
  · exact ⟨⟨[], by simp [applyAll, Write.apply], by simp⟩,
      ⟨fun h => Or.inr h, fun _ => hl⟩,
      fun h => absurd hl h, hkept⟩

/-- After recovery the state is the fold of the tree eventlog, the cursor
at or past all of it, and every operation this boot measured in it: the
loop starts from a node with nothing half done. -/
theorem recover_settles {Signed : Pub T M I D → M → Prop}
    (ha : Assumptions H init Signed)
    {n : Node T M I D} (hr : Reach H init Signed n) {pub : Pub T M I D} {m : M}
    (hchk : Checked pub) (hfol : Follows pub n.state m) (hsig : Signed pub m)
    {ws : List (Write T M I D)} {st : State T M D}
    (hrec : recover H init n pub (n.state.getD (fresh init pub.treeId)) =
      some (ws, st)) :
    rootAt init (applyAll ws n) = rootOf H init (applyAll ws n).log ∧
      st.root = rootOf H init (applyAll ws n).log ∧
      (∀ l ∈ (applyAll ws n).log, l.seq ≤ st.lastSeq) ∧
      ∀ e ∈ (applyAll ws n).measured, e ∈ events (applyAll ws n).log := by
  obtain ⟨-, hrel, -⟩ := recover_inv H init ha.binds ha.hash_inj ha.hash_init
    (reach_inv H init ha hr) hchk hfol hsig hrec
  obtain ⟨L1, L2, hl, hm⟩ := hrel.suffix
  refine ⟨hrel.clean.1, hrel.root.trans hrel.clean.1,
    fun l h => Int.le_trans (hrel.clean.2 l h) hrel.le, fun e he => ?_⟩
  rw [hm] at he
  rw [hl, events, List.map_append]
  exact List.mem_append_right _ he

/-- The recorded state is the fold of the operations the tree eventlog
says the node applied, but for a run stopped between appending the
pending operation's line and writing the state, which recovery
completes. -/
theorem state_is_fold {Signed : Pub T M I D → M → Prop}
    (ha : Assumptions H init Signed)
    {n : Node T M I D} (hr : Reach H init Signed n) :
    (rootAt init n = rootOf H init n.log ∧ ∀ l ∈ n.log, l.seq ≤ cursor n) ∨
      ∃ p L0, n.pending = some p ∧ cursor n < p.seq ∧
        n.log = L0 ++ [⟨p.seq, p.digest, H (rootOf H init L0) p.digest⟩] ∧
        rootAt init n = rootOf H init L0 ∧ ∀ l ∈ L0, l.seq ≤ cursor n := by
  rcases (reach_inv H init ha hr).window with ⟨hc, -⟩ | ⟨-, -, -, hc, -⟩ |
      ⟨p, L0, hp, hlt, hl, hroot, hbelow, -⟩
  · exact Or.inl hc
  · exact Or.inl hc
  · exact Or.inr ⟨p, L0, hp, hlt, hl, hroot, hbelow⟩

/-- `tree_event_replay()` never refuses the tree eventlog of a reachable
node, so recovery never fails on it. -/
theorem replay_not_bad {Signed : Pub T M I D → M → Prop}
    (ha : Assumptions H init Signed)
    {n : Node T M I D} (hr : Reach H init Signed n) :
    replay H init n.log ≠ .bad := by
  have hrep := (reach_inv H init ha hr).replays
  cases hl : n.log with
  | nil => simp [replay]
  | cons l ls =>
    rw [← hl, replay_ok H init hrep (by simp [hl])]
    simp

/-! ### The operations applied are the signed ones -/

/-- Every line of the tree eventlog is an operation of a signed
publication of the recorded tree. -/
theorem applied_signed {Signed : Pub T M I D → M → Prop}
    (ha : Assumptions H init Signed)
    {n : Node T M I D} (hr : Reach H init Signed n) {s : State T M D}
    (hst : n.state = some s) {l : Line D} (hl : l ∈ n.log) :
    ∃ p m, Signed p m ∧ p.treeId = s.treeId ∧
      ∃ o ∈ p.ops, o.seq = l.seq ∧ o.digest = l.digest :=
  (reach_inv H init ha hr).applied s hst l hl

/-- When the signer never gives one sequence number two operations within
a tree, every line of the tree eventlog is the operation every signed
publication of the recorded tree has at that number. -/
theorem applied_consistent {Signed : Pub T M I D → M → Prop}
    (ha : Assumptions H init Signed)
    (hcons : ∀ p m p' m', Signed p m → Signed p' m' → p.treeId = p'.treeId →
      ∀ o ∈ p.ops, ∀ o' ∈ p'.ops, o.seq = o'.seq → o = o')
    {n : Node T M I D} (hr : Reach H init Signed n) {s : State T M D}
    (hst : n.state = some s) {l : Line D} (hl : l ∈ n.log)
    {q : Pub T M I D} {mq : M} (hq : Signed q mq) (hqt : q.treeId = s.treeId)
    {o : Op I D} (ho : o ∈ q.ops) (hos : o.seq = l.seq) :
    o.digest = l.digest := by
  obtain ⟨p, m, hp, hpt, o', ho', h1, h2⟩ := applied_signed H init ha hr hst hl
  have := hcons q mq p m hq hp (hqt.trans hpt.symm) o ho o' ho'
    (hos.trans h1.symm)
  rw [this, h2]

end run

end Shirudo.TreeSync
