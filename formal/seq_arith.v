(* ===================================================================== *)
(* Coq formalization of src/tcp/seq.rs — TCP sequence-number arithmetic  *)
(* (RFC 9293 §3.4), proof layer 2 of PLAN.md.                            *)
(*                                                                       *)
(* Fidelity contract: every Definition below mirrors one Rust function   *)
(* formula-for-formula. A SeqNr is a canonical u32 (0 <= x < 2^32);      *)
(* `wrap` is u32 wrapping arithmetic; `to_signed` is the two's-          *)
(* complement reinterpretation performed by Rust's `as i32`, so even     *)
(* the signed-cast comparison trick in `lt` is modeled and PROVED        *)
(* (ltb_charact), not assumed.                                           *)
(*                                                                       *)
(*   Rust (src/tcp/seq.rs)                  Coq                          *)
(*   ----------------------------------    ---------------------------- *)
(*   add(n)  = wrapping_add(n)             addw a n = wrap (a + n)      *)
(*   sub(n)  = wrapping_sub(n)             subw a n = wrap (a - n)      *)
(*   since(e)= wrapping_sub(e)             since s e = wrap (s - e)     *)
(*   lt(o)   = (o - self) as i32 > 0       ltb a b =                    *)
(*                                           0 <? to_signed (since b a) *)
(*   le(o)   = !o.lt(self)                 leb a b = negb (ltb b a)     *)
(*   gt(o)   = o.lt(self)                  gtb a b = ltb b a            *)
(*   ge(o)   = !self.lt(o)                 geb a b = negb (ltb a b)     *)
(*   max / min                             maxw / minw                  *)
(*   in_window(s,l) = since(s) < l         in_windowb x s l =           *)
(*                                           since x s <? l             *)
(*                                                                       *)
(* Check with:  formal/prove.sh  (coqc seq_arith.v)                      *)
(* ===================================================================== *)

Require Import ZArith Lia Bool.
Local Open Scope Z_scope.

Definition W  : Z := 4294967296.   (* 2^32 *)
Definition HW : Z := 2147483648.   (* 2^31 *)

Lemma W_is_2_32 : W = 2 ^ 32.  Proof. reflexivity. Qed.
Lemma HW_is_2_31 : HW = 2 ^ 31. Proof. reflexivity. Qed.
Lemma W_is_2HW : W = 2 * HW.    Proof. reflexivity. Qed.

(* A canonical u32 value. *)
Definition canon (x : Z) : Prop := 0 <= x < W.

(* u32 wrapping arithmetic. *)
Definition wrap (d : Z) : Z := d mod W.

(* Rust `as i32` on a canonical u32: two's-complement reinterpretation. *)
Definition to_signed (d : Z) : Z := if d <? HW then d else d - W.

(* --- the eight operations of seq.rs ---------------------------------- *)

Definition addw (a n : Z) : Z := wrap (a + n).
Definition subw (a n : Z) : Z := wrap (a - n).
Definition since (s e : Z) : Z := wrap (s - e).
Definition ltb (a b : Z) : bool := 0 <? to_signed (since b a).
Definition leb (a b : Z) : bool := negb (ltb b a).
Definition gtb (a b : Z) : bool := ltb b a.
Definition geb (a b : Z) : bool := negb (ltb a b).
Definition maxw (a b : Z) : Z := if geb a b then a else b.
Definition minw (a b : Z) : Z := if leb a b then a else b.
Definition in_windowb (x start len : Z) : bool := since x start <? len.

(* The gt/ge mirrors are definitionally the flipped lt/le, exactly as in
   Rust — recorded as theorems so a future edit cannot silently diverge. *)
Lemma gt_lt_dual : forall a b, gtb a b = ltb b a.
Proof. reflexivity. Qed.
Lemma ge_le_dual : forall a b, geb a b = leb b a.
Proof. reflexivity. Qed.

(* --- wrap toolbox ----------------------------------------------------- *)

Lemma W_pos : 0 < W.
Proof. unfold W; lia. Qed.

Lemma wrap_canon : forall d, canon (wrap d).
Proof. intros d. unfold canon, wrap. apply Z.mod_pos_bound, W_pos. Qed.

Lemma since_canon : forall s e, canon (since s e).
Proof. intros; apply wrap_canon. Qed.

Lemma wrap_small : forall d, 0 <= d < W -> wrap d = d.
Proof. intros; apply Z.mod_small; auto. Qed.

Lemma wrap_add_W : forall d, wrap (d + W) = wrap d.
Proof.
  intros d. unfold wrap.
  replace (d + W) with (d + 1 * W) by lia.
  apply Z_mod_plus_full.
Qed.

Lemma wrap_neg : forall d, -W <= d < 0 -> wrap d = d + W.
Proof.
  intros d Hd. rewrite <- wrap_add_W. apply wrap_small. lia.
Qed.

Lemma wrap_big : forall d, W <= d < 2 * W -> wrap d = d - W.
Proof.
  intros d Hd.
  replace d with (d - W + W) at 1 by lia.
  rewrite wrap_add_W.
  apply wrap_small; lia.
Qed.

(* The two shapes `since` can take on canonical inputs: everything else
   reduces to case analysis over this lemma plus linear arithmetic. *)
Lemma since_cases : forall a b, canon a -> canon b ->
  (a <= b /\ since b a = b - a) \/ (b < a /\ since b a = b - a + W).
Proof.
  intros a b Ha Hb. unfold canon in *. unfold since.
  destruct (Z_le_gt_dec a b) as [Hle | Hgt].
  - left.  split; [exact Hle | apply wrap_small; lia].
  - right. split; [lia | apply wrap_neg; lia].
Qed.

Lemma since_self : forall a, canon a -> since a a = 0.
Proof.
  intros a Ha. unfold since.
  replace (a - a) with 0 by lia. apply wrap_small. unfold W; lia.
Qed.

Lemma since_zero_eq : forall a b, canon a -> canon b -> since b a = 0 -> a = b.
Proof.
  intros a b Ha Hb H.
  destruct (since_cases a b Ha Hb) as [[? E] | [? E]]; unfold canon in *; lia.
Qed.

(* Distances in the two directions are complementary around the ring. *)
Lemma since_antisym : forall a b, canon a -> canon b ->
  (a = b /\ since b a = 0 /\ since a b = 0) \/ since b a + since a b = W.
Proof.
  intros a b Ha Hb.
  destruct (since_cases a b Ha Hb) as [[Hab E1] | [Hab E1]];
  destruct (since_cases b a Hb Ha) as [[Hba E2] | [Hba E2]].
  - left. assert (a = b) by lia. subst. rewrite since_self by auto. auto.
  - right. lia.
  - right. lia.
  - lia.
Qed.

(* Triangle identity: distances compose modulo 2^32 — unconditionally. *)
Lemma since_sum_mod : forall a b c, canon a -> canon b -> canon c ->
  since c a = wrap (since c b + since b a).
Proof.
  intros a b c Ha Hb Hc.
  destruct (since_cases b c Hb Hc) as [[H1 E1] | [H1 E1]];
  destruct (since_cases a b Ha Hb) as [[H2 E2] | [H2 E2]];
  rewrite E1, E2; unfold since.
  - f_equal; lia.
  - replace (c - b + (b - a + W)) with (c - a + W) by lia.
    now rewrite wrap_add_W.
  - replace (c - b + W + (b - a)) with (c - a + W) by lia.
    now rewrite wrap_add_W.
  - replace (c - b + W + (b - a + W)) with (c - a + W + W) by lia.
    now rewrite !wrap_add_W.
Qed.

(* …and exactly, when the legs do not span the whole ring. *)
Lemma since_sum_exact : forall a b c, canon a -> canon b -> canon c ->
  since c b + since b a < W ->
  since c a = since c b + since b a.
Proof.
  intros a b c Ha Hb Hc Hlt.
  rewrite (since_sum_mod a b c) by auto.
  pose proof (since_canon c b). pose proof (since_canon b a).
  unfold canon in *. apply wrap_small. lia.
Qed.

(* --- add/sub/since algebra ------------------------------------------- *)

Lemma add_canon : forall a n, canon (addw a n).
Proof. intros; apply wrap_canon. Qed.

Lemma sub_canon : forall a n, canon (subw a n).
Proof. intros; apply wrap_canon. Qed.

(* Advancing by n and asking "how far since?" returns n: the round-trip
   the send/receive bookkeeping performs constantly. *)
Lemma add_since : forall a n, canon a -> 0 <= n < W ->
  since (addw a n) a = n.
Proof.
  intros a n Ha Hn. unfold canon in Ha. unfold addw, since.
  destruct (Z_lt_ge_dec (a + n) W) as [Hs | Hb].
  - rewrite (wrap_small (a + n)) by lia.
    replace (a + n - a) with n by lia. apply wrap_small; lia.
  - rewrite (wrap_big (a + n)) by lia.
    replace (a + n - W - a) with (n - W) by lia.
    rewrite wrap_neg by lia. lia.
Qed.

(* A point equals its base advanced by their distance. *)
Lemma since_add : forall a b, canon a -> canon b ->
  addw a (since b a) = b.
Proof.
  intros a b Ha Hb. unfold canon in *.
  destruct (since_cases a b Ha Hb) as [[H E] | [H E]]; rewrite E; unfold addw.
  - replace (a + (b - a)) with b by lia. apply wrap_small; lia.
  - replace (a + (b - a + W)) with (b + W) by lia.
    rewrite wrap_add_W. apply wrap_small; lia.
Qed.

Lemma add_sub : forall a n, canon a -> 0 <= n < W ->
  subw (addw a n) n = a.
Proof.
  intros a n Ha Hn. unfold canon in Ha. unfold addw, subw.
  destruct (Z_lt_ge_dec (a + n) W) as [Hs | Hb].
  - rewrite (wrap_small (a + n)) by lia.
    replace (a + n - n) with a by lia. apply wrap_small; lia.
  - rewrite (wrap_big (a + n)) by lia.
    replace (a + n - W - n) with (a - W) by lia.
    rewrite wrap_neg by lia. lia.
Qed.

Lemma sub_add : forall a n, canon a -> 0 <= n < W ->
  addw (subw a n) n = a.
Proof.
  intros a n Ha Hn. unfold canon in Ha. unfold subw, addw.
  destruct (Z_le_gt_dec n a) as [Hs | Hb].
  - rewrite (wrap_small (a - n)) by lia.
    replace (a - n + n) with a by lia. apply wrap_small; lia.
  - rewrite (wrap_neg (a - n)) by lia.
    replace (a - n + W + n) with (a + W) by lia.
    rewrite wrap_add_W. apply wrap_small; lia.
Qed.

(* --- the signed-cast trick, characterized ----------------------------- *)

(* `self < other` (the Rust `as i32 > 0` formula) holds exactly when the
   forward distance is in [1, 2^31 - 1]: nonzero and within a half-space.
   This bridges the implementation trick to the RFC 9293 meaning. *)
Lemma ltb_charact : forall a b, canon a -> canon b ->
  (ltb a b = true <-> 1 <= since b a <= HW - 1).
Proof.
  intros a b Ha Hb. unfold ltb, to_signed.
  pose proof (since_canon b a) as Hc. unfold canon in Hc.
  destruct (since b a <? HW) eqn:E.
  - apply Z.ltb_lt in E. rewrite Z.ltb_lt. lia.
  - apply Z.ltb_ge in E. rewrite Z.ltb_lt. unfold W, HW in *. lia.
Qed.

(* `self <= other` holds exactly when the forward distance is at most
   2^31 — note it INCLUDES the antipode (distance exactly 2^31), where
   le holds in both directions while lt holds in neither. The half-space
   precondition (distances < 2^31) under which the code operates excludes
   that anomaly; S-INV-1 keeps SND windows well inside it. *)
Lemma leb_charact : forall a b, canon a -> canon b ->
  (leb a b = true <-> since b a <= HW).
Proof.
  intros a b Ha Hb. unfold leb.
  rewrite negb_true_iff.
  pose proof (since_canon b a) as Hba. pose proof (since_canon a b) as Hab.
  unfold canon in Hba, Hab.
  destruct (since_antisym a b Ha Hb) as [[Heq [E1 E2]] | Hsum].
  - rewrite E1. split; intro; [unfold HW; lia |].
    destruct (ltb b a) eqn:L; auto.
    apply ltb_charact in L; auto. lia.
  - split; intro H.
    + destruct (ltb b a) eqn:L; [discriminate |].
      destruct (Z_le_gt_dec (since b a) HW) as [|Hgt]; auto.
      exfalso.
      assert (1 <= since a b <= HW - 1) by (unfold W, HW in *; lia).
      assert (ltb b a = true) by (apply ltb_charact; auto).
      congruence.
    + destruct (ltb b a) eqn:L; auto.
      apply ltb_charact in L; auto. unfold W, HW in *. lia.
Qed.

(* --- order laws -------------------------------------------------------- *)

Lemma lt_irrefl : forall a, canon a -> ltb a a = false.
Proof.
  intros a Ha. destruct (ltb a a) eqn:E; auto.
  apply ltb_charact in E; auto. rewrite since_self in E; auto. lia.
Qed.

Lemma le_refl : forall a, canon a -> leb a a = true.
Proof. intros a Ha. unfold leb. now rewrite lt_irrefl. Qed.

(* Asymmetry holds GLOBALLY — no half-space precondition needed. *)
Lemma lt_asym : forall a b, canon a -> canon b ->
  ltb a b = true -> ltb b a = false.
Proof.
  intros a b Ha Hb H.
  apply ltb_charact in H; auto.
  destruct (ltb b a) eqn:E; auto.
  apply ltb_charact in E; auto.
  destruct (since_antisym a b Ha Hb) as [[_ [E1 _]] | Hsum]; unfold W, HW in *; lia.
Qed.

Lemma le_total : forall a b, canon a -> canon b ->
  leb a b = true \/ leb b a = true.
Proof.
  intros a b Ha Hb. unfold leb.
  destruct (ltb b a) eqn:E1.
  - right. now rewrite (lt_asym b a Hb Ha E1).
  - left. reflexivity.
Qed.

(* Antisymmetry, stated honestly: mutual `le` means equal OR antipodal.
   Under the half-space precondition the antipode is excluded and le is
   a genuine partial order. *)
Lemma le_antisym_cases : forall a b, canon a -> canon b ->
  leb a b = true -> leb b a = true ->
  a = b \/ (since b a = HW /\ since a b = HW).
Proof.
  intros a b Ha Hb H1 H2.
  apply leb_charact in H1; auto. apply leb_charact in H2; auto.
  destruct (since_antisym a b Ha Hb) as [[Heq _] | Hsum]; auto.
  right. unfold W, HW in *. lia.
Qed.

Lemma le_antisym : forall a b, canon a -> canon b ->
  since b a < HW ->
  leb a b = true -> leb b a = true -> a = b.
Proof.
  intros a b Ha Hb Hh H1 H2.
  destruct (le_antisym_cases a b Ha Hb H1 H2) as [| [E _]]; [auto | lia].
Qed.

(* Transitivity within a half-space (fails globally: three points can
   chase each other around the ring; the hypothesis `since c a < HW`
   pins the span). The le/lt mixed forms are the shapes the code uses,
   e.g. SND.UNA <= SEG.ACK <= SND.NXT chains. *)
Lemma lt_trans : forall a b c, canon a -> canon b -> canon c ->
  ltb a b = true -> ltb b c = true -> since c a < HW ->
  ltb a c = true.
Proof.
  intros a b c Ha Hb Hc H1 H2 Hh.
  apply ltb_charact in H1; auto. apply ltb_charact in H2; auto.
  assert (E : since c a = since c b + since b a).
  { apply since_sum_exact; auto. unfold W, HW in *. lia. }
  apply ltb_charact; auto. rewrite E in *. lia.
Qed.

Lemma le_lt_trans : forall a b c, canon a -> canon b -> canon c ->
  leb a b = true -> ltb b c = true -> since c a < HW ->
  ltb a c = true.
Proof.
  intros a b c Ha Hb Hc H1 H2 Hh.
  apply leb_charact in H1; auto. apply ltb_charact in H2; auto.
  pose proof (since_canon b a) as Q. unfold canon in Q.
  assert (E : since c a = since c b + since b a).
  { apply since_sum_exact; auto. unfold W, HW in *. lia. }
  apply ltb_charact; auto. rewrite E in *. lia.
Qed.

Lemma lt_le_trans : forall a b c, canon a -> canon b -> canon c ->
  ltb a b = true -> leb b c = true -> since c a < HW ->
  ltb a c = true.
Proof.
  intros a b c Ha Hb Hc H1 H2 Hh.
  apply ltb_charact in H1; auto. apply leb_charact in H2; auto.
  pose proof (since_canon c b) as Q. unfold canon in Q.
  assert (E : since c a = since c b + since b a).
  { apply since_sum_exact; auto. unfold W, HW in *. lia. }
  apply ltb_charact; auto. rewrite E in *. lia.
Qed.

(* For le/le chains the span hypothesis must bound the SUM of the legs:
   two distances of exactly 2^31 (antipodes) chain around the ring. *)
Lemma le_trans : forall a b c, canon a -> canon b -> canon c ->
  leb a b = true -> leb b c = true -> since c b + since b a <= HW ->
  leb a c = true.
Proof.
  intros a b c Ha Hb Hc H1 H2 Hh.
  apply leb_charact in H1; auto. apply leb_charact in H2; auto.
  assert (E : since c a = since c b + since b a).
  { apply since_sum_exact; auto. unfold W, HW in *. lia. }
  apply leb_charact; auto. rewrite E in *. lia.
Qed.

(* --- max / min --------------------------------------------------------- *)

Lemma max_either : forall a b, maxw a b = a \/ maxw a b = b.
Proof. intros. unfold maxw. destruct (geb a b); auto. Qed.

Lemma min_either : forall a b, minw a b = a \/ minw a b = b.
Proof. intros. unfold minw. destruct (leb a b); auto. Qed.

(* max is an upper bound of both arguments — unconditionally, because le
   is total (asymmetry of lt needs no half-space hypothesis). *)
Lemma max_upper : forall a b, canon a -> canon b ->
  leb a (maxw a b) = true /\ leb b (maxw a b) = true.
Proof.
  intros a b Ha Hb. unfold maxw, geb.
  destruct (ltb a b) eqn:E; simpl.
  - split; [| apply le_refl; auto].
    unfold leb. now rewrite (lt_asym a b Ha Hb E).
  - split; [apply le_refl; auto |].
    unfold leb. now rewrite E.
Qed.

Lemma min_lower : forall a b, canon a -> canon b ->
  leb (minw a b) a = true /\ leb (minw a b) b = true.
Proof.
  intros a b Ha Hb. unfold minw, leb.
  destruct (ltb b a) eqn:E; simpl.
  - split; [now rewrite (lt_asym b a Hb Ha E) | now rewrite lt_irrefl].
  - split; [now rewrite lt_irrefl | now rewrite E].
Qed.

(* --- the window test: implementation <-> specification ----------------- *)

Lemma in_window_zero : forall x s, in_windowb x s 0 = false.
Proof.
  intros. unfold in_windowb. apply Z.ltb_ge.
  pose proof (since_canon x s). unfold canon in *. lia.
Qed.

(* THE theorem: the O(1) implementation predicate `since x s < len`
   accepts exactly the set RFC 9293 §3.4 describes — the points reachable
   from `start` by advancing fewer than `len` bytes. *)
Theorem in_window_spec : forall x s len, canon x -> canon s -> 0 <= len <= W ->
  (in_windowb x s len = true <-> exists k, 0 <= k < len /\ x = addw s k).
Proof.
  intros x s len Hx Hs Hlen. unfold in_windowb.
  split.
  - intro H. apply Z.ltb_lt in H.
    exists (since x s).
    pose proof (since_canon x s). unfold canon in *.
    split; [lia |]. symmetry. apply since_add; auto.
  - intros [k [Hk ->]].
    apply Z.ltb_lt. rewrite add_since; auto; lia.
Qed.

(* RFC 9293 §3.9: ACK acceptability "SND.UNA < SEG.ACK =< SND.NXT".
   The code's check `una.lt(ack) && ack.le(nxt)` accepts exactly the
   sequence numbers obtained by advancing SND.UNA by 1..=in-flight bytes,
   provided the send window obeys the half-space invariant (S-INV-1
   keeps `since nxt una` < 2^30, well under 2^31). *)
Theorem ack_acceptance : forall una nxt ack,
  canon una -> canon nxt -> canon ack ->
  since nxt una < HW ->
  (andb (ltb una ack) (leb ack nxt) = true <->
   exists k, 1 <= k <= since nxt una /\ ack = addw una k).
Proof.
  intros una nxt ack Hu Hn Ha Hh.
  rewrite andb_true_iff.
  split.
  - intros [Hlt Hle].
    apply ltb_charact in Hlt; auto. apply leb_charact in Hle; auto.
    exists (since ack una).
    split; [| symmetry; apply since_add; auto].
    split; [lia |].
    rewrite (since_sum_exact una ack nxt) by (auto; unfold W, HW in *; lia).
    pose proof (since_canon nxt ack). unfold canon in *. lia.
  - intros [k [Hk ->]].
    pose proof (since_canon nxt una). unfold canon in *.
    assert (Hka : since (addw una k) una = k)
      by (apply add_since; auto; unfold W, HW in *; lia).
    split.
    + apply ltb_charact; auto using add_canon. rewrite Hka. lia.
    + apply leb_charact; auto using add_canon.
      (* since nxt (una+k) = since nxt una - k, by the triangle identity *)
      pose proof (since_sum_mod una (addw una k) nxt Hu (add_canon una k) Hn) as T.
      rewrite Hka in T.
      pose proof (since_canon nxt (addw una k)) as Hm. unfold canon in Hm.
      destruct (Z_lt_ge_dec (since nxt (addw una k) + k) W) as [Hs | Hb].
      * rewrite wrap_small in T by lia. lia.
      * rewrite wrap_big in T by lia. lia.
Qed.

(* --- the seq.rs unit tests, replayed as computations ------------------- *)

Example wraparound_add  : addw (W - 2) 10 = 8.
Proof. reflexivity. Qed.
Example wraparound_lt   : ltb (W - 2) 8 = true /\ ltb 8 (W - 2) = false.
Proof. split; reflexivity. Qed.
Example wraparound_since: since 8 (W - 2) = 10.
Proof. reflexivity. Qed.
Example wraparound_sub  : subw 8 10 = W - 2.
Proof. reflexivity. Qed.
Example window_wrapped  : in_windowb (addw (W - 5) 9) (W - 5) 10 = true
                       /\ in_windowb (addw (W - 5) 10) (W - 5) 10 = false.
Proof. split; reflexivity. Qed.
Example equal_not_less  : ltb 1000 1000 = false /\ leb 1000 1000 = true.
Proof. split; reflexivity. Qed.

(* ===================================================================== *)
(* What the code relies on, lemma by lemma:                              *)
(*  - ltb_charact / leb_charact: the `as i32` cast implements the RFC    *)
(*    half-space comparison (every seq comparison in tcp/conn).          *)
(*  - lt_asym / le_total: max/min and ordering decisions never dead-end. *)
(*  - *_trans + le_antisym (half-space): the SND.UNA <= ack <= SND.NXT   *)
(*    style chains in input.rs are sound while S-INV-1 holds.            *)
(*  - add_since / since_add / add_sub / sub_add: buffer index <-> seq    *)
(*    round-trips in sendbuf/recvbuf.                                    *)
(*  - since_sum_exact: distance bookkeeping (data_sent, in-flight).      *)
(*  - in_window_spec / ack_acceptance: the O(1) acceptance predicates    *)
(*    equal their RFC 9293 set definitions.                              *)
(* Known, documented anomaly: at distance exactly 2^31 (the antipode),   *)
(* le holds both ways while lt holds neither (le_antisym_cases). The     *)
(* half-space invariant S-INV-1 keeps live windows < 2^30, far from it.  *)
(* ===================================================================== *)
