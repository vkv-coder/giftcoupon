-- Gift Coupon (gc_) — fix two real fraud vectors found during a
-- portfolio-wide check.
--
-- 1. CRITICAL: gc_companies self-insert had no restriction on approved
--    or balance. gc_generate_coupons() only checks admin_user_id =
--    auth.uid(), approved = true, and balance sufficiency - all
--    satisfiable by a self-inserted row. Anyone could self-insert
--    {approved: true, balance: 999999, store_id: <any real approved
--    store>} and immediately mint real, redeemable gift coupons against
--    a real store, at zero cost. Only one legitimate company exists in
--    production right now (verified), so this had not yet been
--    exploited, but was live and exposed.
--
-- 2. gc_stores self-insert/update had no restriction on approved either
--    - same self-approval bypass class as already fixed on Homebites'
--    hb_suppliers, skipping gc_admin_approve_store() (which IS properly
--    token-gated - the bug is purely that the raw table path bypassed
--    it entirely).
--
-- NOT touched: stores setting balance/approved on THEIR OWN companies
-- via store_manages_companies (UPDATE) is left as-is - that's the
-- intended business relationship (a store extends credit to companies
-- it onboards), not a bug. The actual hole was a stranger self-creating
-- an approved, funded company with no store involved at all.
--
-- Verified read-only before applying: the "must equal old value" lock
-- pattern works correctly against real gc_stores data (both existing
-- rows, already approved=true, correctly evaluate as unchanged).

-- ── gc_stores: split the single ALL policy so approved/approved_at
--    can only ever be set by the admin RPC, never by the store itself.
drop policy if exists "store_owner_access" on gc_stores;

create policy "store_select_own" on gc_stores
  for select to public
  using (owner_user_id = auth.uid());

create policy "store_insert_own" on gc_stores
  for insert to public
  with check (owner_user_id = auth.uid() and approved = false);

create policy "store_update_own" on gc_stores
  for update to public
  using (owner_user_id = auth.uid())
  with check (
    owner_user_id = auth.uid()
    and approved = (select old_row.approved from gc_stores old_row where old_row.store_id = gc_stores.store_id)
    and approved_at is not distinct from (select old_row.approved_at from gc_stores old_row where old_row.store_id = gc_stores.store_id)
  );

create policy "store_delete_own" on gc_stores
  for delete to public
  using (owner_user_id = auth.uid());

-- ── gc_companies: force approved=false and balance=0 on self-insert.
--    Real approval/funding only ever happens via the owning store's own
--    store_manages_companies UPDATE, unaffected by this change.
drop policy if exists "company_admin_inserts" on gc_companies;

create policy "company_admin_inserts" on gc_companies
  for insert to public
  with check (admin_user_id = auth.uid() and approved = false and balance = 0);
