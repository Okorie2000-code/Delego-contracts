/// All permission / delegation errors surfaced by the contract.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum PermissionError {
    /// The requested sub-scope includes bits not present in the parent scope.
    PrivilegeEscalationAttempt,
    /// The delegation chain has already reached the maximum allowed depth.
    MaxDelegationDepthExceeded,
    /// The referenced delegation record does not exist.
    DelegationNotFound,
    /// The caller does not own the delegation record they are trying to act on.
    Unauthorized,
}

impl core::fmt::Display for PermissionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::PrivilegeEscalationAttempt => {
                write!(f, "sub-scope exceeds parent scope (privilege escalation)")
            }
            Self::MaxDelegationDepthExceeded => {
                write!(f, "delegation depth limit (2) exceeded")
            }
            Self::DelegationNotFound => write!(f, "delegation record not found"),
            Self::Unauthorized => write!(f, "caller is not the owner of this delegation"),
        }
    }
}
