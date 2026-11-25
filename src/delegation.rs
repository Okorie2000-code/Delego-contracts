use crate::errors::PermissionError;
use std::collections::HashMap;

/// Maximum number of times a delegation can be sub-delegated.
/// Depth 0 = owner GåÆ delegate (first grant).
/// Depth 1 = delegate GåÆ sub-delegate (one level down).
/// Depth 2 = sub-delegate GåÆ sub-sub-delegate GÇö REJECTED.
pub const MAX_DELEGATION_DEPTH: u8 = 2;

/// A unique identifier for a delegation record (e.g. a hash or counter).
pub type DelegationId = u64;

/// A bitmask representing the set of permissions granted.
/// Each bit corresponds to a distinct permission flag.
pub type Scope = u32;

/// An account / address identifier (simplified for this contract).
pub type AccountId = u64;

/// Immutable record stored on-chain for every delegation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegationRecord {
    /// Who created this delegation.
    pub owner: AccountId,
    /// Who received the delegation.
    pub delegate: AccountId,
    /// Permissions granted (bitmask).
    pub scope: Scope,
    /// How many hops from the original owner (0 = direct grant from owner).
    pub depth: u8,
    /// ID of the parent delegation this was derived from (`None` for root grants).
    pub parent_id: Option<DelegationId>,
}

// ---------------------------------------------------------------------------
// Pure validation helpers
// ---------------------------------------------------------------------------

/// Validate that `sub_scope` is a strict subset of `parent_scope`.
///
/// Every bit set in `sub_scope` must also be set in `parent_scope`.
/// Returns `Err(PermissionError::PrivilegeEscalationAttempt)` if not.
pub fn validate_sub_delegation(parent_scope: Scope, sub_scope: Scope) -> Result<(), PermissionError> {
    if (parent_scope & sub_scope) != sub_scope {
        return Err(PermissionError::PrivilegeEscalationAttempt);
    }
    Ok(())
}

/// Validate that creating a delegation one level below `parent_depth` does
/// not exceed `MAX_DELEGATION_DEPTH`.
pub fn validate_depth(parent_depth: u8) -> Result<u8, PermissionError> {
    let new_depth = parent_depth + 1;
    if new_depth >= MAX_DELEGATION_DEPTH {
        return Err(PermissionError::MaxDelegationDepthExceeded);
    }
    Ok(new_depth)
}

// ---------------------------------------------------------------------------
// Stateful store (simulates on-chain storage)
// ---------------------------------------------------------------------------

/// In-memory store that owns all delegation records.
#[derive(Debug, Default)]
pub struct DelegationStore {
    records: HashMap<DelegationId, DelegationRecord>,
    next_id: DelegationId,
}

impl DelegationStore {
    pub fn new() -> Self {
        Self::default()
    }

    // -----------------------------------------------------------------------
    // Write operations
    // -----------------------------------------------------------------------

    /// Grant a root delegation directly from an owner (depth = 0).
    pub fn grant(
        &mut self,
        owner: AccountId,
        delegate: AccountId,
        scope: Scope,
    ) -> DelegationId {
        let id = self.next_id;
        self.next_id += 1;
        self.records.insert(
            id,
            DelegationRecord {
                owner,
                delegate,
                scope,
                depth: 0,
                parent_id: None,
            },
        );
        id
    }

    /// Sub-delegate: the holder of `parent_id` grants `sub_scope` to `new_delegate`.
    ///
    /// Enforces:
    /// 1. `parent_id` must exist.
    /// 2. `caller` must be the `delegate` of the parent record.
    /// 3. `sub_scope` must be a subset of the parent's scope.
    /// 4. The resulting depth must be < `MAX_DELEGATION_DEPTH`.
    pub fn sub_delegate(
        &mut self,
        caller: AccountId,
        parent_id: DelegationId,
        new_delegate: AccountId,
        sub_scope: Scope,
    ) -> Result<DelegationId, PermissionError> {
        // Borrow the parent record immutably first, copy what we need.
        let (parent_scope, parent_depth) = {
            let parent = self
                .records
                .get(&parent_id)
                .ok_or(PermissionError::DelegationNotFound)?;

            if parent.delegate != caller {
                return Err(PermissionError::Unauthorized);
            }

            (parent.scope, parent.depth)
        };

        // Validate scope subset.
        validate_sub_delegation(parent_scope, sub_scope)?;

        // Validate and compute new depth.
        let new_depth = validate_depth(parent_depth)?;

        let id = self.next_id;
        self.next_id += 1;
        self.records.insert(
            id,
            DelegationRecord {
                owner: caller,
                delegate: new_delegate,
                scope: sub_scope,
                depth: new_depth,
                parent_id: Some(parent_id),
            },
        );
        Ok(id)
    }

    // -----------------------------------------------------------------------
    // Read operations
    // -----------------------------------------------------------------------

    pub fn get(&self, id: DelegationId) -> Option<&DelegationRecord> {
        self.records.get(&id)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Unit tests for validate_sub_delegation
    // -----------------------------------------------------------------------

    #[test]
    fn exact_scope_is_valid() {
        // Sub-scope identical to parent is allowed.
        assert_eq!(validate_sub_delegation(0b1111, 0b1111), Ok(()));
    }

    #[test]
    fn strict_subset_is_valid() {
        assert_eq!(validate_sub_delegation(0b1111, 0b0101), Ok(()));
        assert_eq!(validate_sub_delegation(0b1010, 0b0010), Ok(()));
    }

    #[test]
    fn zero_scope_is_always_valid() {
        assert_eq!(validate_sub_delegation(0b0000, 0b0000), Ok(()));
        assert_eq!(validate_sub_delegation(0b1111, 0b0000), Ok(()));
    }

    #[test]
    fn privilege_escalation_single_bit() {
        // sub_scope has bit 4 set; parent does not.
        assert_eq!(
            validate_sub_delegation(0b0111, 0b1111),
            Err(PermissionError::PrivilegeEscalationAttempt)
        );
    }

    #[test]
    fn privilege_escalation_multiple_bits() {
        assert_eq!(
            validate_sub_delegation(0b0001, 0b1111),
            Err(PermissionError::PrivilegeEscalationAttempt)
        );
    }

    #[test]
    fn privilege_escalation_disjoint_scopes() {
        // parent = 0b1010, sub = 0b0101 GÇö no bits overlap at all.
        assert_eq!(
            validate_sub_delegation(0b1010, 0b0101),
            Err(PermissionError::PrivilegeEscalationAttempt)
        );
    }

    // -----------------------------------------------------------------------
    // Unit tests for validate_depth
    // -----------------------------------------------------------------------

    #[test]
    fn depth_0_produces_depth_1() {
        assert_eq!(validate_depth(0), Ok(1));
    }

    #[test]
    fn depth_1_is_rejected() {
        // parent is already at depth 1; child would be depth 2 == MAX.
        assert_eq!(
            validate_depth(1),
            Err(PermissionError::MaxDelegationDepthExceeded)
        );
    }

    // -----------------------------------------------------------------------
    // Integration tests via DelegationStore
    // -----------------------------------------------------------------------

    const OWNER: AccountId = 1;
    const DELEGATE_A: AccountId = 2;
    const DELEGATE_B: AccountId = 3;
    const DELEGATE_C: AccountId = 4;

    fn setup() -> (DelegationStore, DelegationId) {
        let mut store = DelegationStore::new();
        // Owner grants DELEGATE_A full permissions: 0b1111.
        let root_id = store.grant(OWNER, DELEGATE_A, 0b1111);
        (store, root_id)
    }

    #[test]
    fn sub_delegate_with_subset_scope_succeeds() {
        let (mut store, root_id) = setup();
        // DELEGATE_A sub-delegates 0b0011 to DELEGATE_B GÇö valid subset.
        let sub_id = store
            .sub_delegate(DELEGATE_A, root_id, DELEGATE_B, 0b0011)
            .expect("valid sub-delegation should succeed");

        let record = store.get(sub_id).unwrap();
        assert_eq!(record.scope, 0b0011);
        assert_eq!(record.depth, 1);
        assert_eq!(record.owner, DELEGATE_A);
        assert_eq!(record.delegate, DELEGATE_B);
        assert_eq!(record.parent_id, Some(root_id));
    }

    #[test]
    fn sub_delegate_with_exact_scope_succeeds() {
        let (mut store, root_id) = setup();
        let sub_id = store
            .sub_delegate(DELEGATE_A, root_id, DELEGATE_B, 0b1111)
            .expect("same-scope sub-delegation should succeed");

        assert_eq!(store.get(sub_id).unwrap().scope, 0b1111);
    }

    #[test]
    fn sub_delegate_privilege_escalation_is_rejected() {
        let mut store = DelegationStore::new();
        // DELEGATE_A only has 0b0011.
        let root_id = store.grant(OWNER, DELEGATE_A, 0b0011);

        // DELEGATE_A tries to grant 0b1111 GÇö escalation.
        let result = store.sub_delegate(DELEGATE_A, root_id, DELEGATE_B, 0b1111);
        assert_eq!(result, Err(PermissionError::PrivilegeEscalationAttempt));
    }

    #[test]
    fn sub_delegate_max_depth_exceeded() {
        let (mut store, root_id) = setup();

        // Depth 0 GåÆ 1: DELEGATE_A GåÆ DELEGATE_B.
        let sub_id = store
            .sub_delegate(DELEGATE_A, root_id, DELEGATE_B, 0b1111)
            .unwrap();

        // Depth 1 GåÆ 2: DELEGATE_B GåÆ DELEGATE_C GÇö must be rejected.
        let result = store.sub_delegate(DELEGATE_B, sub_id, DELEGATE_C, 0b0001);
        assert_eq!(result, Err(PermissionError::MaxDelegationDepthExceeded));
    }

    #[test]
    fn sub_delegate_on_nonexistent_parent_returns_not_found() {
        let (mut store, _) = setup();
        let result = store.sub_delegate(DELEGATE_A, 9999, DELEGATE_B, 0b0001);
        assert_eq!(result, Err(PermissionError::DelegationNotFound));
    }

    #[test]
    fn sub_delegate_by_non_owner_returns_unauthorized() {
        let (mut store, root_id) = setup();
        // DELEGATE_B is not the delegate of root_id GÇö DELEGATE_A is.
        let result = store.sub_delegate(DELEGATE_B, root_id, DELEGATE_C, 0b0001);
        assert_eq!(result, Err(PermissionError::Unauthorized));
    }

    #[test]
    fn sub_delegate_with_zero_scope_always_valid() {
        let (mut store, root_id) = setup();
        let sub_id = store
            .sub_delegate(DELEGATE_A, root_id, DELEGATE_B, 0b0000)
            .expect("zero-scope sub-delegation should succeed");
        assert_eq!(store.get(sub_id).unwrap().scope, 0);
    }

    #[test]
    fn multiple_independent_sub_delegations_do_not_interfere() {
        let (mut store, root_id) = setup();

        let id1 = store
            .sub_delegate(DELEGATE_A, root_id, DELEGATE_B, 0b0011)
            .unwrap();
        let id2 = store
            .sub_delegate(DELEGATE_A, root_id, DELEGATE_C, 0b1100)
            .unwrap();

        assert_ne!(id1, id2);
        assert_eq!(store.get(id1).unwrap().scope, 0b0011);
        assert_eq!(store.get(id2).unwrap().scope, 0b1100);
    }
}
