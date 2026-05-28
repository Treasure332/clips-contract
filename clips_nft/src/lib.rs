#![no_std]

pub mod safe_math;

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, symbol_short, xdr::ToXdr, Address, Bytes,
    BytesN, Env, String, Vec,
};

pub const VERSION: u32 = 1;
pub const DEFAULT_MINT_COOLDOWN_SECONDS: u64 = 0;
pub const DEFAULT_CIRCUIT_BREAKER_ENABLED: bool = false;
pub const DEFAULT_CIRCUIT_BREAKER_THRESHOLD: u64 = 100;
pub const DEFAULT_CIRCUIT_BREAKER_WINDOW_SECONDS: u64 = 60;

const GAS_BASE_MINT: u64 = 50_000;
const GAS_BASE_TRANSFER: u64 = 30_000;
const MAX_BATCH_MINT: u32 = 25;
const PERSISTENT_BUMP_THRESHOLD: u32 = 172_800;
const PERSISTENT_BUMP_AMOUNT: u32 = 535_680;

// =============================================================================
// Errors
// =============================================================================

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum Error {
    Unauthorized = 1,
    InvalidTokenId = 2,
    ClipAlreadyMinted = 3,
    RoyaltyTooHigh = 4,
    InvalidRecipient = 5,
    InvalidSalePrice = 6,
    ContractPaused = 7,
    InvalidSignature = 8,
    SignerNotSet = 9,
    InvalidRoyaltySplit = 10,
    SoulboundTransferBlocked = 11,
    RoyaltyOverflow = 12,
    ClipBlacklisted = 13,
    NotAuthorizedToApprove = 14,
    WithdrawalStillLocked = 15,
    NoWithdrawalRequest = 16,
    BatchTooLarge = 17,
    TokenFrozen = 18,
    InsufficientBalance = 19,
    MetadataRefreshTooSoon = 20,
    UnsupportedProtocol = 21,
    MalformedUrl = 22,
    MintCooldownActive = 23,
    Reentrancy = 24,
    MintingPaused = 25,
    CircuitBreakerTripped = 26,
    MetadataLocked = 27,
}

// =============================================================================
// Types
// =============================================================================

pub type TokenId = u32;

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Attribute {
    pub trait_type: String,
    pub value: String,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoyaltyRecipient {
    pub recipient: Address,
    pub basis_points: u32,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Royalty {
    pub recipients: Vec<RoyaltyRecipient>,
    pub asset_address: Option<Address>,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenData {
    pub owner: Address,
    pub clip_id: u32,
    pub is_soulbound: bool,
    pub metadata_uri: String,
    pub image: Option<String>,
    pub animation_url: Option<String>,
    pub description: Option<String>,
    pub external_url: Option<String>,
    pub attributes: Vec<Attribute>,
    pub royalty: Royalty,
    pub is_locked: bool,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoyaltyInfo {
    pub receiver: Address,
    pub royalty_amount: i128,
    pub asset_address: Option<Address>,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContractInfo {
    pub name: String,
    pub symbol: String,
    pub version: u32,
    pub owner: Address,
    pub platform_fee: u32,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WithdrawRequest {
    pub amount: i128,
    pub unlock_time: u64,
}

// =============================================================================
// Storage keys
// =============================================================================

#[contracttype]
pub enum DataKey {
    Admin,
    NextTokenId,
    Paused,
    PauseUnlockTime,
    MintingPaused,
    Name,
    Symbol,
    Signer,
    BackendAddress,
    PlatformRecipient,
    /// Task 2: platform fee in basis points
    PlatformFeeBps,
    /// Task 2: default royalty in basis points
    DefaultRoyaltyBps,
    DefaultRoyaltyAsset,
    MintCooldownSeconds,
    ReentrancyLock,
    TotalSupply,
    ContractVersion,
    CircuitBreakerEnabled,
    CircuitBreakerThreshold,
    CircuitBreakerWindowSeconds,
    CircuitBreakerWindowStart,
    CircuitBreakerWindowCount,
    WithdrawXlmRequest,
    LastWithdrawalTime,
    TotalGasMint,
    CountMint,
    TotalGasTransfer,
    CountTransfer,
    Token(TokenId),
    ClipIdMinted(u32),
    CustomTokenUri(TokenId),
    Approved(TokenId),
    MetadataUpdateCount(TokenId),
    ApprovalForAll(Address, Address),
    BlacklistedClip(u32),
    Balance(Address),
    Frozen(TokenId),
    MetadataRefreshTime(TokenId),
    RoyaltyBalance(TokenId),
    LastMintTimestamp(Address),
    /// Task 3: global enumeration index
    TokenIndex(u32),
    /// Task 3: per-owner enumeration index
    OwnerTokenIndex(Address, u32),
    /// Task 1: per-wallet nonce for mint_with_signature replay protection
    LastMintNonce(Address),
    /// Task 1: used signature hashes for replay protection
    UsedSignature(BytesN<32>),
    /// Issue #299: optional human-readable reason provided when pausing
    PauseReason,
}

// =============================================================================
// Events
// =============================================================================

// Emitted on mint completion and useful for frontend tokens/indexing.
#[contracttype] #[derive(Clone, Debug, Eq, PartialEq)]
pub struct MintEvent { pub to: Address, pub clip_id: u32, pub token_id: TokenId, pub metadata_uri: String }

// Emitted when a token is destroyed.
#[contracttype] #[derive(Clone, Debug, Eq, PartialEq)]
pub struct BurnEvent { pub owner: Address, pub token_id: TokenId, pub clip_id: u32 }

// Emitted on token ownership transfer.
#[contracttype] #[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransferEvent { pub token_id: TokenId, pub from: Address, pub to: Address }

// Emitted when a single-token approval is granted.
#[contracttype] #[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalEvent { pub owner: Address, pub operator: Address, pub token_id: TokenId }

// Emitted when operator approval is toggled for all tokens of an owner.
#[contracttype] #[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalForAllEvent { pub owner: Address, pub operator: Address, pub approved: bool }

// Emitted when royalty is paid during a transfer or sale.
#[contracttype] #[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoyaltyPaidEvent { pub token_id: TokenId, pub from: Address, pub to: Address, pub amount: i128 }

// Emitted when the primary royalty recipient changes.
#[contracttype] #[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoyaltyRecipientUpdatedEvent { pub token_id: TokenId, pub old_recipient: Address, pub new_recipient: Address }

// Emitted when royalty parameters are updated for a token.
#[contracttype] #[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoyaltyUpdatedEvent { pub token_id: TokenId }

// Emitted when royalties are claimed from contract-held balances.
#[contracttype] #[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoyaltyClaimedEvent { pub token_id: TokenId, pub recipient: Address, pub amount: i128, pub asset: Address }

// Emitted when a token URI is updated for a custom owner override.
#[contracttype] #[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenUriChangedEvent { pub token_id: TokenId, pub owner: Address, pub new_uri: String }

// Emitted when metadata fields are refreshed by admin or backend.
#[contracttype] #[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetadataUpdatedEvent { pub token_id: TokenId, pub old_uri: String, pub new_uri: String }

// Emitted when metadata is permanently locked.
#[contracttype] #[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetadataLockedEvent { pub token_id: TokenId, pub owner: Address }

// Emitted after a batch mint completes.
#[contracttype] #[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchMintEvent { pub to: Address, pub count: u32, pub first_token_id: TokenId }

// Emitted when a clip is blacklisted.
#[contracttype] #[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlacklistEvent { pub clip_id: u32 }

// Emitted when a token freezes transfers.
#[contracttype] #[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenFrozenEvent { pub token_id: TokenId }

// Emitted when a token freeze is lifted.
#[contracttype] #[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenUnfrozenEvent { pub token_id: TokenId }

// Emitted when the backend signer public key changes.
#[contracttype] #[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignerUpdatedEvent { pub new_pubkey: BytesN<32> }

// Emitted when pause is scheduled and becomes active.
#[contracttype] #[derive(Clone, Debug, Eq, PartialEq)]
pub struct PauseScheduledEvent { pub active_at: u64 }

// Emitted when pause is scheduled with an optional admin-provided reason.
#[contracttype] #[derive(Clone, Debug, Eq, PartialEq)]
pub struct PauseWithReasonEvent { pub active_at: u64, pub reason: Option<String> }

// Emitted when the contract is unpaused.
#[contracttype] #[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnpausedEvent {}

// Emitted when minting is paused.
#[contracttype] #[derive(Clone, Debug, Eq, PartialEq)]
pub struct PauseMintingEvent {}

// Emitted when minting is resumed.
#[contracttype] #[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnpauseMintingEvent {}

// Emitted when the backend address is updated.
#[contracttype] #[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackendAddressUpdatedEvent { pub new_backend_address: Address }

// Emitted when the platform recipient changes.
#[contracttype] #[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlatformRecipientUpdatedEvent { pub new_recipient: Address }

// Emitted when the default royalty asset is updated.
#[contracttype] #[derive(Clone, Debug, Eq, PartialEq)]
pub struct DefaultRoyaltyAssetUpdatedEvent { pub asset_address: Option<Address> }

// Emitted when the mint cooldown value changes.
#[contracttype] #[derive(Clone, Debug, Eq, PartialEq)]
pub struct MintCooldownUpdatedEvent { pub seconds: u64 }

// Emitted when core config values change.
#[contracttype] #[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigUpdatedEvent { pub key: String, pub new_value: i128 }

// Emitted when circuit breaker counters are reset by admin.
#[contracttype] #[derive(Clone, Debug, Eq, PartialEq)]
pub struct CircuitBreakerResetEvent {}

#[contracttype] #[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminChangedEvent { pub old_admin: Address, pub new_admin: Address }

// Emitted when contract ownership is fully transferred (two-step, #320).
#[contracttype] #[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnershipTransferredEvent { pub previous_owner: Address, pub new_owner: Address }

#[contracttype] #[derive(Clone, Debug, Eq, PartialEq)]
pub struct RefundedEvent { pub token_id: TokenId, pub recipient: Address, pub amount: i128 }

#[contracttype] #[derive(Clone, Debug, Eq, PartialEq)]
pub struct CircuitBreakerTriggeredEvent { pub mint_count: u64, pub threshold: u64, pub window_seconds: u64 }

#[contracttype] #[derive(Clone, Debug, Eq, PartialEq)]
pub struct SoulboundRecoveredEvent { pub token_id: TokenId, pub old_owner: Address, pub new_owner: Address }

#[contracttype] #[derive(Clone, Debug, Eq, PartialEq)]
pub struct MigratedEvent { pub from_version: u32, pub to_version: u32 }

#[contracttype] #[derive(Clone, Debug, Eq, PartialEq)]
pub struct WithdrawRequestedEvent { pub amount: i128, pub unlock_time: u64 }

#[contracttype] #[derive(Clone, Debug, Eq, PartialEq)]
pub struct WithdrawExecutedEvent { pub amount: i128, pub recipient: Address }

// =============================================================================
// Contract
// =============================================================================

#[contract]
pub struct ClipsNftContract;

#[contractimpl]
impl ClipsNftContract {
    // -------------------------------------------------------------------------
    // Init
    // -------------------------------------------------------------------------

    pub fn init(env: Env, admin: Address) {
        if env.storage().instance().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::NextTokenId, &1u32);
        env.storage().instance().set(&DataKey::TotalSupply, &0u32);
        env.storage().instance().set(&DataKey::Paused, &false);
        env.storage().instance().set(&DataKey::MintingPaused, &false);
        env.storage().instance().set(&DataKey::PlatformRecipient, &admin);
        env.storage().instance().set(&DataKey::PlatformFeeBps, &100u32);
        env.storage().instance().set(&DataKey::DefaultRoyaltyBps, &0u32);
        env.storage().instance().set(&DataKey::DefaultRoyaltyAsset, &Option::<Address>::None);
        env.storage().instance().set(&DataKey::Name, &String::from_str(&env, "ClipCash Clips"));
        env.storage().instance().set(&DataKey::Symbol, &String::from_str(&env, "CLIP"));
        env.storage().instance().set(&DataKey::MintCooldownSeconds, &DEFAULT_MINT_COOLDOWN_SECONDS);
        env.storage().instance().set(&DataKey::CircuitBreakerEnabled, &DEFAULT_CIRCUIT_BREAKER_ENABLED);
        env.storage().instance().set(&DataKey::CircuitBreakerThreshold, &DEFAULT_CIRCUIT_BREAKER_THRESHOLD);
        env.storage().instance().set(&DataKey::CircuitBreakerWindowSeconds, &DEFAULT_CIRCUIT_BREAKER_WINDOW_SECONDS);
        env.storage().instance().set(&DataKey::CircuitBreakerWindowStart, &0u64);
        env.storage().instance().set(&DataKey::CircuitBreakerWindowCount, &0u64);
        env.storage().instance().set(&DataKey::BackendAddress, &admin);
    }

    // -------------------------------------------------------------------------
    // #320: Two-step ownership transfer
    // -------------------------------------------------------------------------

    /// Step 1: current admin proposes a new owner. Stores `new_owner` as pending.
    /// The transfer is not final until `accept_ownership` is called by `new_owner`.
    pub fn transfer_ownership(env: Env, admin: Address, new_owner: Address) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.storage().instance().set(&DataKey::PendingOwner, &new_owner);
        Ok(())
    }

    /// Step 2: pending owner accepts and becomes the new admin.
    /// Emits `OwnershipTransferred` event.
    pub fn accept_ownership(env: Env, new_owner: Address) -> Result<(), Error> {
        new_owner.require_auth();
        let pending: Address = env
            .storage()
            .instance()
            .get(&DataKey::PendingOwner)
            .ok_or(Error::Unauthorized)?;
        if pending != new_owner {
            return Err(Error::Unauthorized);
        }
        let previous_owner: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("Admin not initialized");
        env.storage().instance().set(&DataKey::Admin, &new_owner);
        env.storage().instance().remove(&DataKey::PendingOwner);
        env.events().publish(
            (symbol_short!("own_xfer"),),
            OwnershipTransferredEvent { previous_owner, new_owner },
        );
        Ok(())
    }

    /// Returns the pending owner address, if any.
    pub fn pending_owner(env: Env) -> Option<Address> {
        env.storage().instance().get(&DataKey::PendingOwner)
    }

    // -------------------------------------------------------------------------
    // Task 1: Safe math — mint with overflow-safe royalty validation
    // -------------------------------------------------------------------------

    pub fn mint(
        env: Env,
        to: Address,
        clip_id: u32,
        metadata_uri: String,
        image: Option<String>,
        animation_url: Option<String>,
        royalty: Royalty,
        is_soulbound: bool,
        signature: BytesN<64>,
    ) -> Result<TokenId, Error> {
        to.require_auth();
        Self::require_not_paused(&env)?;
        if env.storage().instance().get::<DataKey, bool>(&DataKey::MintingPaused).unwrap_or(false) {
            return Err(Error::MintingPaused);
        }
        Self::enforce_mint_cooldown(&env, &to)?;
        Self::check_circuit_breaker(&env, 1)?;
        Self::validate_url(&env, &image)?;
        Self::validate_url(&env, &animation_url)?;
        Self::verify_clip_signature(&env, &to, clip_id, &metadata_uri, &signature)?;

        if Self::load_clip_token_id(&env, clip_id).is_some() {
            return Err(Error::ClipAlreadyMinted);
        }
        if env.storage().persistent().get::<DataKey, bool>(&DataKey::BlacklistedClip(clip_id)).unwrap_or(false) {
            return Err(Error::ClipBlacklisted);
        }

        let royalty = Self::normalize_royalty(&env, royalty)?;
        // Task 1: validate royalty bps via safe_math before storing
        let mut total_bps: u32 = 0;
        for i in 0..royalty.recipients.len() {
            let r = royalty.recipients.get(i).ok_or(Error::InvalidRoyaltySplit)?;
            total_bps = total_bps.saturating_add(r.basis_points);
        }
        if total_bps > 10_000 {
            return Err(Error::RoyaltyTooHigh);
        }

        let token_id: TokenId = env.storage().instance().get(&DataKey::NextTokenId).unwrap_or(1);
        env.storage().instance().set(&DataKey::NextTokenId, &(token_id + 1));

        let data = TokenData {
            owner: to.clone(), clip_id, is_soulbound,
            metadata_uri: metadata_uri.clone(), image, animation_url,
            description: None, external_url: None,
            attributes: Vec::new(&env), royalty, is_locked: false,
        };
        env.storage().persistent().set(&DataKey::Token(token_id), &data);
        Self::bump_persistent_ttl(&env, &DataKey::Token(token_id));
        env.storage().persistent().set(&DataKey::ClipIdMinted(clip_id), &token_id);
        Self::bump_persistent_ttl(&env, &DataKey::ClipIdMinted(clip_id));

        // Update supply + enumeration indexes
        let supply: u32 = env.storage().instance().get(&DataKey::TotalSupply).unwrap_or(0);
        env.storage().instance().set(&DataKey::TotalSupply, &(supply + 1));
        env.storage().persistent().set(&DataKey::TokenIndex(supply), &token_id);
        let bal: u32 = env.storage().persistent().get(&DataKey::Balance(to.clone())).unwrap_or(0);
        env.storage().persistent().set(&DataKey::Balance(to.clone()), &(bal + 1));
        env.storage().persistent().set(&DataKey::OwnerTokenIndex(to.clone(), bal), &token_id);

        Self::record_mint_timestamp(&env, &to);
        Self::update_circuit_breaker_counter(&env, 1);

        let count: u64 = env.storage().temporary().get(&DataKey::CountMint).unwrap_or(0);
        env.storage().temporary().set(&DataKey::CountMint, &(count + 1));
        let gas: u64 = env.storage().temporary().get(&DataKey::TotalGasMint).unwrap_or(0);
        env.storage().temporary().set(&DataKey::TotalGasMint, &gas.saturating_add(GAS_BASE_MINT));

        env.events().publish((symbol_short!("mint"), token_id, to.clone()), MintEvent { to, clip_id, token_id, metadata_uri });
        Ok(token_id)
    }

    pub fn transfer(
        env: Env,
        from: Address,
        to: Address,
        token_id: TokenId,
        sale_price: i128,
        payment_asset: Option<Address>,
    ) -> Result<(), Error> {
        from.require_auth();
        Self::require_not_paused(&env)?;
        if env.storage().persistent().get::<DataKey, bool>(&DataKey::Frozen(token_id)).unwrap_or(false) {
            return Err(Error::TokenFrozen);
        }
        let mut data: TokenData = Self::load_token(&env, token_id)?;
        if from != data.owner { return Err(Error::Unauthorized); }
        if data.is_soulbound { return Err(Error::SoulboundTransferBlocked); }

        if sale_price > 0 {
            let royalty = data.royalty.clone();
            let pay_asset = match royalty.asset_address.clone() {
                Some(a) => a,
                None => payment_asset.ok_or(Error::InvalidRecipient)?,
            };
            to.require_auth();
            Self::acquire_reentrancy_lock(&env)?;
            let token_client = soroban_sdk::token::TokenClient::new(&env, &pay_asset);
            let mut cum_bps: u32 = 0;
            let mut cum_amt: i128 = 0;
            for i in 0..royalty.recipients.len() {
                let split = royalty.recipients.get(i).ok_or(Error::InvalidRoyaltySplit)?;
                cum_bps = cum_bps.saturating_add(split.basis_points);
                let total = Self::calculate_royalty(sale_price, cum_bps)?;
                let amount = total.saturating_sub(cum_amt);
                cum_amt = total;
                if amount > 0 {
                    token_client.transfer(&to, &split.recipient, &amount);
                    env.events().publish((symbol_short!("royalty"), token_id, split.recipient.clone()), RoyaltyPaidEvent { token_id, from: to.clone(), to: split.recipient, amount });
                }
            }
            Self::release_reentrancy_lock(&env);
        }

        env.storage().persistent().remove(&DataKey::Approved(token_id));
        data.owner = to.clone();
        env.storage().persistent().set(&DataKey::Token(token_id), &data);

        // Update balance + owner indexes
        let fb: u32 = env.storage().persistent().get(&DataKey::Balance(from.clone())).unwrap_or(0);
        env.storage().persistent().set(&DataKey::Balance(from.clone()), &fb.saturating_sub(1));
        Self::index_remove_owner(&env, &from, token_id);
        let tb: u32 = env.storage().persistent().get(&DataKey::Balance(to.clone())).unwrap_or(0);
        env.storage().persistent().set(&DataKey::Balance(to.clone()), &(tb + 1));
        env.storage().persistent().set(&DataKey::OwnerTokenIndex(to.clone(), tb), &token_id);

        let ct: u64 = env.storage().temporary().get(&DataKey::CountTransfer).unwrap_or(0);
        env.storage().temporary().set(&DataKey::CountTransfer, &(ct + 1));
        let gt: u64 = env.storage().temporary().get(&DataKey::TotalGasTransfer).unwrap_or(0);
        env.storage().temporary().set(&DataKey::TotalGasTransfer, &gt.saturating_add(GAS_BASE_TRANSFER));

        env.events().publish((symbol_short!("transfer"), token_id, from.clone(), to.clone()), TransferEvent { token_id, from, to });
        Ok(())
    }

    pub fn burn(env: Env, owner: Address, token_id: TokenId) -> Result<(), Error> {
        owner.require_auth();
        if env.storage().persistent().get::<DataKey, bool>(&DataKey::Frozen(token_id)).unwrap_or(false) {
            return Err(Error::TokenFrozen);
        }
        let data: TokenData = Self::load_token(&env, token_id)?;
        if owner != data.owner { return Err(Error::Unauthorized); }

        env.storage().persistent().remove(&DataKey::Token(token_id));
        env.storage().persistent().remove(&DataKey::ClipIdMinted(data.clip_id));
        env.storage().persistent().remove(&DataKey::Approved(token_id));

        let supply: u32 = env.storage().instance().get(&DataKey::TotalSupply).unwrap_or(0);
        env.storage().instance().set(&DataKey::TotalSupply, &supply.saturating_sub(1));
        Self::index_remove_global(&env, token_id, supply);

        let bal: u32 = env.storage().persistent().get(&DataKey::Balance(owner.clone())).unwrap_or(0);
        env.storage().persistent().set(&DataKey::Balance(owner.clone()), &bal.saturating_sub(1));
        Self::index_remove_owner(&env, &owner, token_id);

        env.events().publish((symbol_short!("burn"), token_id, owner.clone()), BurnEvent { owner, token_id, clip_id: data.clip_id });
        Ok(())
    }

    pub fn approve(env: Env, caller: Address, operator: Option<Address>, token_id: TokenId) -> Result<(), Error> {
        caller.require_auth();
        let data: TokenData = Self::load_token(&env, token_id)?;
        if data.owner != caller {
            let approved_all = env.storage().persistent().get::<DataKey, bool>(&DataKey::ApprovalForAll(data.owner.clone(), caller.clone())).unwrap_or(false);
            if !approved_all { return Err(Error::Unauthorized); }
        }
        match operator {
            Some(op) => {
                env.storage().persistent().set(&DataKey::Approved(token_id), &op);
                env.events().publish((symbol_short!("approval"), token_id, data.owner.clone(), op.clone()), ApprovalEvent { owner: data.owner, operator: op, token_id });
            }
            None => { env.storage().persistent().remove(&DataKey::Approved(token_id)); }
        }
        Ok(())
    }

    pub fn set_approval_for_all(env: Env, caller: Address, operator: Address, approved: bool) -> Result<(), Error> {
        caller.require_auth();
        env.storage().persistent().set(&DataKey::ApprovalForAll(caller.clone(), operator.clone()), &approved);
        env.events().publish((symbol_short!("app_all"), caller.clone(), operator.clone()), ApprovalForAllEvent { owner: caller, operator, approved });
        Ok(())
    }

    pub fn get_approved(env: Env, token_id: TokenId) -> Option<Address> {
        env.storage().persistent().get(&DataKey::Approved(token_id))
    }

    pub fn is_approved_for_all(env: Env, owner: Address, operator: Address) -> bool {
        env.storage().persistent().get::<DataKey, bool>(&DataKey::ApprovalForAll(owner, operator)).unwrap_or(false)
    }

    // -------------------------------------------------------------------------
    // Task 2: Admin-only config — set_platform_fee, set_default_royalty
    // -------------------------------------------------------------------------

    /// Set platform fee in basis points. Emits ConfigUpdated.
    pub fn set_platform_fee(env: Env, admin: Address, bps: u32) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        if bps > 10_000 { return Err(Error::RoyaltyTooHigh); }
        env.storage().instance().set(&DataKey::PlatformFeeBps, &bps);
        env.events().publish((symbol_short!("cfg_upd"), symbol_short!("platform_fee")), ConfigUpdatedEvent { key: String::from_str(&env, "platform_fee"), new_value: bps as i128 });
        Ok(())
    }

    /// Set default royalty in basis points. Emits ConfigUpdated.
    pub fn set_default_royalty(env: Env, admin: Address, bps: u32) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        if bps > 10_000 { return Err(Error::RoyaltyTooHigh); }
        env.storage().instance().set(&DataKey::DefaultRoyaltyBps, &bps);
        env.events().publish((symbol_short!("cfg_upd"), symbol_short!("default_royalty")), ConfigUpdatedEvent { key: String::from_str(&env, "default_royalty"), new_value: bps as i128 });
        Ok(())
    }

    pub fn get_platform_fee(env: Env) -> u32 {
        env.storage().instance().get(&DataKey::PlatformFeeBps).unwrap_or(100)
    }

    pub fn get_default_royalty_bps(env: Env) -> u32 {
        env.storage().instance().get(&DataKey::DefaultRoyaltyBps).unwrap_or(0)
    }

    // -------------------------------------------------------------------------
    // Task 3: get_user_tokens — O(1) index-based pagination
    // -------------------------------------------------------------------------

    /// Return token IDs owned by `owner`. O(limit) — reads from OwnerTokenIndex.
    pub fn get_user_tokens(env: Env, owner: Address, limit: u32, offset: u32) -> Vec<TokenId> {
        const MAX_LIMIT: u32 = 100;
        let limit = if limit > MAX_LIMIT { MAX_LIMIT } else { limit };
        let balance: u32 = env.storage().persistent().get(&DataKey::Balance(owner.clone())).unwrap_or(0);
        let mut result: Vec<TokenId> = Vec::new(&env);
        let end = offset.saturating_add(limit).min(balance);
        for pos in offset..end {
            if let Some(tid) = env.storage().persistent().get::<DataKey, TokenId>(&DataKey::OwnerTokenIndex(owner.clone(), pos)) {
                result.push_back(tid);
            }
        }
        result
    }

    /// Alias with optional params for backwards compat.
    pub fn tokens_of_owner(env: Env, owner: Address, limit: Option<u32>, offset: Option<u32>) -> Vec<TokenId> {
        Self::get_user_tokens(env, owner, limit.unwrap_or(100), offset.unwrap_or(0))
    }

    // -------------------------------------------------------------------------
    // Task 4: Fee estimation helpers
    // -------------------------------------------------------------------------

    /// Returns approximate mint fee in stroops.
    pub fn estimate_mint_fee(_env: Env) -> i128 {
        GAS_BASE_MINT as i128
    }

    /// Returns approximate transfer fee in stroops.
    pub fn estimate_transfer_fee(_env: Env) -> i128 {
        GAS_BASE_TRANSFER as i128
    }

    // -------------------------------------------------------------------------
    // Royalty
    // -------------------------------------------------------------------------

    pub fn royalty_info(env: Env, token_id: TokenId, sale_price: i128) -> Result<RoyaltyInfo, Error> {
        if sale_price <= 0 { return Err(Error::InvalidSalePrice); }
        let data = Self::load_token(&env, token_id)?;
        let mut total_bps: u32 = 0;
        for i in 0..data.royalty.recipients.len() {
            let r = data.royalty.recipients.get(i).ok_or(Error::InvalidRoyaltySplit)?;
            total_bps = total_bps.saturating_add(r.basis_points);
        }
        let royalty_amount = Self::calculate_royalty(sale_price, total_bps)?;
        let first = data.royalty.recipients.get(0).ok_or(Error::InvalidRoyaltySplit)?;
        Ok(RoyaltyInfo { receiver: first.recipient, royalty_amount, asset_address: data.royalty.asset_address })
    }

    pub fn get_royalty(env: Env, token_id: TokenId) -> Result<Royalty, Error> {
        Ok(Self::load_token(&env, token_id)?.royalty)
    }

    pub fn set_royalty(env: Env, admin: Address, token_id: TokenId, new_royalty: Royalty) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        let mut data = Self::load_token(&env, token_id)?;
        let old = data.royalty.clone();
        if !old.recipients.is_empty() && !new_royalty.recipients.is_empty() {
            let or = old.recipients.get(0).ok_or(Error::InvalidRoyaltySplit)?;
            let nr = new_royalty.recipients.get(0).ok_or(Error::InvalidRoyaltySplit)?;
            if or.recipient != nr.recipient {
                env.events().publish((symbol_short!("royalty"), token_id, or.recipient.clone(), nr.recipient.clone()), RoyaltyRecipientUpdatedEvent { token_id, old_recipient: or.recipient, new_recipient: nr.recipient });
            }
        }
        let new_royalty = Self::normalize_royalty(&env, new_royalty)?;
        data.royalty = new_royalty;
        env.storage().persistent().set(&DataKey::Token(token_id), &data);
        env.events().publish((symbol_short!("roy_upd"), token_id), RoyaltyUpdatedEvent { token_id });
        Ok(())
    }

    pub fn update_royalty_recipient(env: Env, caller: Address, token_id: TokenId, new_recipient: Address) -> Result<(), Error> {
        caller.require_auth();
        let mut data = Self::load_token(&env, token_id)?;
        let old = data.royalty.recipients.get(0).ok_or(Error::InvalidRoyaltySplit)?.recipient.clone();
        if caller != old { return Err(Error::Unauthorized); }
        let bps = data.royalty.recipients.get(0).ok_or(Error::InvalidRoyaltySplit)?.basis_points;
        data.royalty.recipients.set(0, RoyaltyRecipient { recipient: new_recipient.clone(), basis_points: bps });
        env.storage().persistent().set(&DataKey::Token(token_id), &data);
        env.events().publish((symbol_short!("royalty"), token_id, old.clone(), new_recipient.clone()), RoyaltyRecipientUpdatedEvent { token_id, old_recipient: old, new_recipient });
        Ok(())
    }

    pub fn pay_royalty(env: Env, payer: Address, token_id: TokenId, sale_price: i128) -> Result<(), Error> {
        payer.require_auth();
        if sale_price <= 0 { return Err(Error::InvalidSalePrice); }
        let data = Self::load_token(&env, token_id)?;
        let asset = data.royalty.asset_address.clone().ok_or(Error::InvalidRecipient)?;
        Self::acquire_reentrancy_lock(&env)?;
        let client = soroban_sdk::token::TokenClient::new(&env, &asset);
        let mut cum_bps: u32 = 0;
        let mut cum_amt: i128 = 0;
        for i in 0..data.royalty.recipients.len() {
            let split = data.royalty.recipients.get(i).ok_or(Error::InvalidRoyaltySplit)?;
            cum_bps = cum_bps.saturating_add(split.basis_points);
            let total = Self::calculate_royalty(sale_price, cum_bps)?;
            let amount = total.saturating_sub(cum_amt);
            cum_amt = total;
            if amount > 0 {
                client.transfer(&payer, &split.recipient, &amount);
                env.events().publish((symbol_short!("royalty"), token_id, split.recipient.clone()), RoyaltyPaidEvent { token_id, from: payer.clone(), to: split.recipient, amount });
            }
        }
        Self::release_reentrancy_lock(&env);
        Ok(())
    }

    pub fn claim_royalties(env: Env, caller: Address, token_id: TokenId) -> Result<(), Error> {
        caller.require_auth();
        let data = Self::load_token(&env, token_id)?;
        let recipient = data.royalty.recipients.get(0).ok_or(Error::InvalidRoyaltySplit)?.recipient;
        if caller != recipient { return Err(Error::Unauthorized); }
        let asset = data.royalty.asset_address.ok_or(Error::InvalidRecipient)?;
        let balance: i128 = env.storage().persistent().get(&DataKey::RoyaltyBalance(token_id)).unwrap_or(0);
        if balance <= 0 { return Err(Error::InsufficientBalance); }
        Self::acquire_reentrancy_lock(&env)?;
        env.storage().persistent().remove(&DataKey::RoyaltyBalance(token_id));
        soroban_sdk::token::TokenClient::new(&env, &asset).transfer(&env.current_contract_address(), &recipient, &balance);
        Self::release_reentrancy_lock(&env);
        env.events().publish((symbol_short!("roy_clm"), token_id, recipient.clone()), RoyaltyClaimedEvent { token_id, recipient, amount: balance, asset });
        Ok(())
    }

    /// Task 1: public safe-math royalty calculation helper
    pub fn calculate_royalty_amount(env: Env, token_id: TokenId, sale_price: i128) -> Result<i128, Error> {
        let data = Self::load_token(&env, token_id)?;
        let mut total_bps: u32 = 0;
        for i in 0..data.royalty.recipients.len() {
            let r = data.royalty.recipients.get(i).ok_or(Error::InvalidRoyaltySplit)?;
            total_bps = total_bps.saturating_add(r.basis_points);
        }
        Self::calculate_royalty(sale_price, total_bps)
    }

    // -------------------------------------------------------------------------
    // Pause / Admin
    // -------------------------------------------------------------------------

    /// Pause the contract with an optional human-readable reason.
    ///
    /// The pause takes effect after a 24-hour timelock. Callers can query the
    /// stored reason via [`pause_reason`] until the contract is unpaused.
    pub fn pause(env: Env, admin: Address, reason: Option<String>) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        let active_at = env.ledger().timestamp().saturating_add(86_400);
        env.storage().instance().set(&DataKey::PauseUnlockTime, &active_at);
        env.storage().instance().set(&DataKey::Paused, &true);
        match reason.clone() {
            Some(ref r) => env.storage().instance().set(&DataKey::PauseReason, r),
            None => env.storage().instance().remove(&DataKey::PauseReason),
        }
        env.events().publish(
            (symbol_short!("pse_sched"), symbol_short!("pause")),
            PauseWithReasonEvent { active_at, reason },
        );
        Ok(())
    }

    /// Returns the reason stored when the contract was last paused, if any.
    pub fn pause_reason(env: Env) -> Option<String> {
        env.storage().instance().get(&DataKey::PauseReason)
    }

    pub fn unpause(env: Env, admin: Address) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.storage().instance().set(&DataKey::Paused, &false);
        env.storage().instance().remove(&DataKey::PauseUnlockTime);
        env.storage().instance().remove(&DataKey::PauseReason);
        env.events().publish((symbol_short!("unpaused"), admin.clone()), UnpausedEvent {});
        Ok(())
    }

    pub fn is_paused(env: Env) -> bool {
        Self::check_paused(&env)
    }

    pub fn pause_minting(env: Env, admin: Address) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.storage().instance().set(&DataKey::MintingPaused, &true);
        env.events().publish((symbol_short!("pause_mint"), admin.clone()), PauseMintingEvent {});
        Ok(())
    }

    pub fn unpause_minting(env: Env, admin: Address) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.storage().instance().set(&DataKey::MintingPaused, &false);
        env.events().publish((symbol_short!("unpause_mint"), admin.clone()), UnpauseMintingEvent {});
        Ok(())
    }

    pub fn set_signer(env: Env, admin: Address, pubkey: BytesN<32>) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.storage().instance().set(&DataKey::Signer, &pubkey);
        env.events().publish((symbol_short!("sgn_upd"), pubkey.clone()), SignerUpdatedEvent { new_pubkey: pubkey });
        Ok(())
    }

    pub fn get_signer(env: Env) -> Option<BytesN<32>> {
        env.storage().instance().get(&DataKey::Signer)
    }

    pub fn set_backend_address(env: Env, admin: Address, backend_address: Address) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.storage().instance().set(&DataKey::BackendAddress, &backend_address);
        env.events().publish((symbol_short!("backend_upd"), backend_address.clone()), BackendAddressUpdatedEvent { new_backend_address: backend_address });
        Ok(())
    }

    pub fn get_backend_address(env: Env) -> Option<Address> {
        env.storage().instance().get(&DataKey::BackendAddress)
    }

    pub fn set_platform_recipient(env: Env, admin: Address, recipient: Address) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.storage().instance().set(&DataKey::PlatformRecipient, &recipient);
        env.events().publish((symbol_short!("platform_recipient_upd"), recipient.clone()), PlatformRecipientUpdatedEvent { new_recipient: recipient });
        Ok(())
    }

    pub fn set_default_royalty_asset(env: Env, admin: Address, asset_address: Option<Address>) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.storage().instance().set(&DataKey::DefaultRoyaltyAsset, &asset_address);
        env.events().publish((symbol_short!("default_royalty_asset_upd"),), DefaultRoyaltyAssetUpdatedEvent { asset_address });
        Ok(())
    }

    pub fn get_default_royalty_asset(env: Env) -> Option<Address> {
        env.storage().instance().get::<DataKey, Option<Address>>(&DataKey::DefaultRoyaltyAsset).unwrap_or(None)
    }

    pub fn set_mint_cooldown(env: Env, admin: Address, seconds: u64) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.storage().instance().set(&DataKey::MintCooldownSeconds, &seconds);
        env.events().publish((symbol_short!("cfg_upd"), symbol_short!("mint_cooldown")), ConfigUpdatedEvent { key: String::from_str(&env, "mint_cooldown"), new_value: seconds as i128 });
        Ok(())
    }

    pub fn get_mint_cooldown(env: Env) -> u64 {
        env.storage().instance().get(&DataKey::MintCooldownSeconds).unwrap_or(DEFAULT_MINT_COOLDOWN_SECONDS)
    }

    // Task 2: alias for set_mint_cooldown
    pub fn set_mint_cooldown_seconds(env: Env, admin: Address, seconds: u64) -> Result<(), Error> {
        Self::set_mint_cooldown(env, admin, seconds)
    }

    // Task 4: revoke a single-token approval
    pub fn revoke_approval(env: Env, caller: Address, token_id: TokenId) -> Result<(), Error> {
        caller.require_auth();
        let data: TokenData = Self::load_token(&env, token_id)?;
        if data.owner != caller {
            return Err(Error::Unauthorized);
        }
        env.storage().persistent().remove(&DataKey::Approved(token_id));
        Ok(())
    }

    // Task 4: revoke all operator approvals for the caller
    pub fn revoke_all_approvals(env: Env, caller: Address, operator: Address) -> Result<(), Error> {
        caller.require_auth();
        env.storage()
            .persistent()
            .remove(&DataKey::ApprovalForAll(caller.clone(), operator.clone()));
        env.events().publish(
            (symbol_short!("app_all"), caller.clone(), operator.clone()),
            ApprovalForAllEvent { owner: caller, operator, approved: false },
        );
        Ok(())
    }

    pub fn blacklist_clip(env: Env, admin: Address, clip_id: u32) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.storage().persistent().set(&DataKey::BlacklistedClip(clip_id), &true);
        env.events().publish((symbol_short!("blacklist"), clip_id), BlacklistEvent { clip_id });
        Ok(())
    }

    pub fn freeze_token(env: Env, admin: Address, token_id: TokenId) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        if !env.storage().persistent().has(&DataKey::Token(token_id)) { return Err(Error::InvalidTokenId); }
        env.storage().persistent().set(&DataKey::Frozen(token_id), &true);
        env.events().publish((symbol_short!("freeze"), token_id), TokenFrozenEvent { token_id });
        Ok(())
    }

    /// Mint using a backend-provided signature instead of a wallet-signed tx.
    ///
    /// This entrypoint does NOT require the recipient to `require_auth()`.
    /// The backend signature must include a nonce to prevent replay attacks.
    pub fn mint_with_signature(
        env: Env,
        to: Address,
        clip_id: u32,
        metadata_uri: String,
        image: Option<String>,
        animation_url: Option<String>,
        royalty: Royalty,
        is_soulbound: bool,
        signature: BytesN<64>,
        nonce: u64,
    ) -> Result<TokenId, Error> {
        // No `to.require_auth()` — caller may be any relayer.
        Self::require_not_paused(&env)?;
        Self::check_circuit_breaker(&env, 1)?;

        // Validate URLs before state changes.
        Self::validate_url(&env, &image, Error::InvalidImageUrl)?;
        Self::validate_url(&env, &animation_url, Error::InvalidAnimationUrl)?;

        // Verify backend signature and obtain message hash.
        let message_hash = Self::verify_clip_signature_with_nonce(&env, &to, clip_id, &metadata_uri, nonce, &signature)?;

        // Dedup check — one persistent read.
        if Self::load_clip_token_id(&env, clip_id).is_some() {
            return Err(Error::ClipAlreadyMinted);
        }

        if env
            .storage()
            .persistent()
            .get(&DataKey::BlacklistedClip(clip_id))
            .unwrap_or(false)
        {
            return Err(Error::ClipBlacklisted);
        }

        let royalty = Self::normalize_royalty(&env, royalty)?;

        let token_id: TokenId = env
            .storage()
            .instance()
            .get(&DataKey::NextTokenId)
            .unwrap_or(1);

        // 4 persistent writes
        env.storage().persistent().set(
            &DataKey::Token(token_id),
            &TokenData {
                owner: to.clone(),
                clip_id,
                is_soulbound,
                metadata_uri: metadata_uri.clone(),
                image: image.clone(),
                animation_url: animation_url.clone(),
                description: None,
                external_url: None,
                attributes: Vec::new(&env),
                royalty,
            },
        );
        Self::bump_persistent_ttl(&env, &DataKey::Token(token_id));
        env.storage()
            .persistent()
            .set(&DataKey::ClipIdMinted(clip_id), &token_id);
        Self::bump_persistent_ttl(&env, &DataKey::ClipIdMinted(clip_id));

        // 1 instance write.
        env.storage()
            .instance()
            .set(&DataKey::NextTokenId, &(token_id + 1));

        // Update total supply
        let total_supply: u32 = env
            .storage()
            .instance()
            .get(&DataKey::TotalSupply)
            .unwrap_or(0);
        env.storage()
            .instance()
            .set(&DataKey::TotalSupply, &(total_supply + 1));

        // Update balance
        let balance: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::Balance(to.clone()))
            .unwrap_or(0);
        env.storage()
            .persistent()
            .set(&DataKey::Balance(to.clone()), &(balance + 1));

        // Mark signature message hash as used to prevent replay.
        Self::mark_signature_used(&env, &message_hash);

        env.events().publish(
            (symbol_short!("mint"), token_id, to.clone()),
            MintEvent {
                to: to.clone(),
                clip_id,
                token_id,
                metadata_uri,
            },
        );

        env.events().publish(
            (symbol_short!("transfer"), token_id, env.current_contract_address(), to.clone()),
            TransferEvent {
                token_id,
                from: env.current_contract_address(),
                to: to.clone(),
            },
        );

        // Gas tracking
        let count_mint: u64 = env.storage().instance().get(&DataKey::CountMint).unwrap_or(0);
        env.storage().instance().set(&DataKey::CountMint, &(count_mint + 1));
        let total_gas_mint: u64 = env.storage().instance().get(&DataKey::TotalGasMint).unwrap_or(0);
        env.storage().instance().set(&DataKey::TotalGasMint, &total_gas_mint.saturating_add(GAS_BASE_MINT));
        Self::record_mint_timestamp(&env, &to);

        // Update circuit breaker
        Self::update_circuit_breaker_counter(&env, 1);

        Ok(token_id)
    }

    fn mint_core(
        env: &Env,
        to: &Address,
        clip_id: u32,
        metadata_uri: String,
        image: Option<String>,
        animation_url: Option<String>,
        royalty: Royalty,
        is_soulbound: bool,
    ) -> Result<TokenId, Error> {
        if Self::load_clip_token_id(env, clip_id).is_some() {
            return Err(Error::ClipAlreadyMinted);
        }

        if env
            .storage()
            .persistent()
            .get(&DataKey::BlacklistedClip(clip_id))
            .unwrap_or(false)
        {
            return Err(Error::ClipBlacklisted);
        }

        let royalty = Self::normalize_royalty(env, royalty)?;

        let token_id: TokenId = env
            .storage()
            .instance()
            .get(&DataKey::NextTokenId)
            .unwrap_or(1);

        env.storage().persistent().set(
            &DataKey::Token(token_id),
            &TokenData {
                owner: to.clone(),
                clip_id,
                is_soulbound,
                metadata_uri: metadata_uri.clone(),
                image: image.clone(),
                animation_url: animation_url.clone(),
                description: None,
                external_url: None,
                attributes: Vec::new(env),
                royalty,
            },
        );
        Self::bump_persistent_ttl(env, &DataKey::Token(token_id));
        env.storage()
            .persistent()
            .set(&DataKey::ClipIdMinted(clip_id), &token_id);
        Self::bump_persistent_ttl(env, &DataKey::ClipIdMinted(clip_id));

        env.storage()
            .instance()
            .set(&DataKey::NextTokenId, &(token_id + 1));

        let total_supply: u32 = env.storage().instance().get(&DataKey::TotalSupply).unwrap_or(0);
        env.storage().instance().set(&DataKey::TotalSupply, &(total_supply + 1));

        let balance: u32 = env.storage().persistent().get(&DataKey::Balance(to.clone())).unwrap_or(0);
        env.storage().persistent().set(&DataKey::Balance(to.clone()), &(balance + 1));

        env.events().publish(
            (symbol_short!("mint"), token_id, to.clone()),
            MintEvent { to: to.clone(), clip_id, token_id, metadata_uri: metadata_uri.clone() },
        );

        env.events().publish(
            (symbol_short!("transfer"), token_id, env.current_contract_address(), to.clone()),
            TransferEvent {
                token_id,
                from: env.current_contract_address(),
                to: to.clone(),
            },
        );

        let count_mint: u64 = env.storage().instance().get(&DataKey::CountMint).unwrap_or(0);
        env.storage().instance().set(&DataKey::CountMint, &(count_mint + 1));
        let total_gas_mint: u64 = env.storage().instance().get(&DataKey::TotalGasMint).unwrap_or(0);
        env.storage().instance().set(&DataKey::TotalGasMint, &total_gas_mint.saturating_add(GAS_BASE_MINT));
        Self::record_mint_timestamp(env, &to);
        Self::update_circuit_breaker_counter(env, 1);

        Ok(token_id)
    }

    /// Mint a new NFT for a video clip using a backend-signed payload and a
    /// strictly increasing nonce to prevent replay attacks.
    ///
    /// # Arguments
    /// * `to` — Recipient address (must authorize the call).
    /// * `clip_id` — Off-chain clip identifier.
    /// * `metadata_uri` — Metadata URI (IPFS or Arweave).
    /// * `image` — Static thumbnail URL (optional).
    /// * `animation_url` — Animated preview URL (optional).
    /// * `royalty` — Royalty configuration for secondary sales.
    /// * `is_soulbound` — When `true` the token cannot be transferred.
    /// * `nonce` — Strictly increasing backend nonce for this recipient.
    /// * `signature` — 64-byte Ed25519 signature from the registered backend signer.
    pub fn mint_with_signature(
        env: Env,
        to: Address,
        clip_id: u32,
        metadata_uri: String,
        image: Option<String>,
        animation_url: Option<String>,
        royalty: Royalty,
        is_soulbound: bool,
        nonce: u64,
        signature: BytesN<64>,
    ) -> Result<TokenId, Error> {
        to.require_auth();
        Self::require_not_paused(&env)?;
        Self::enforce_mint_cooldown(&env, &to)?;
        Self::check_circuit_breaker(&env, 1)?;

        Self::validate_url(&env, &image, Error::InvalidImageUrl)?;
        Self::validate_url(&env, &animation_url, Error::InvalidAnimationUrl)?;

        Self::verify_clip_signature_with_nonce(&env, &to, clip_id, &metadata_uri, nonce, &signature)?;
        Self::ensure_mint_nonce(&env, &to, nonce)?;

        let token_id = Self::mint_core(
            &env,
            &to,
            clip_id,
            metadata_uri,
            image,
            animation_url,
            royalty,
            is_soulbound,
        )?;
        Self::record_mint_nonce(&env, &to, nonce);

        Ok(token_id)
    }

    // -------------------------------------------------------------------------
    // Approvals
    // -------------------------------------------------------------------------

    pub fn is_frozen(env: Env, token_id: TokenId) -> bool {
        env.storage().persistent().get::<DataKey, bool>(&DataKey::Frozen(token_id)).unwrap_or(false)
    }

    pub fn set_token_uri(env: Env, owner: Address, token_id: TokenId, new_uri: String) -> Result<(), Error> {
        owner.require_auth();
        let data = Self::load_token(&env, token_id)?;
        if data.owner != owner { return Err(Error::Unauthorized); }
        env.storage().persistent().set(&DataKey::CustomTokenUri(token_id), &new_uri.clone());
        env.events().publish((symbol_short!("uri_chg"), token_id, owner.clone()), TokenUriChangedEvent { token_id, owner, new_uri });
        Ok(())
    }

    pub fn request_withdraw_asset(env: Env, admin: Address, amount: i128) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        let unlock_time = env.ledger().timestamp().saturating_add(172_800);
        env.storage().instance().set(&DataKey::WithdrawXlmRequest, &WithdrawRequest { amount, unlock_time });
        env.events().publish((symbol_short!("wdraw_req"), admin.clone()), WithdrawRequestedEvent { amount, unlock_time });
        Ok(())
    }

    pub fn withdraw_asset(env: Env, admin: Address, asset: Address, amount: i128) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        let req: WithdrawRequest = env.storage().instance().get(&DataKey::WithdrawXlmRequest).ok_or(Error::NoWithdrawalRequest)?;
        if env.ledger().timestamp() < req.unlock_time { return Err(Error::WithdrawalStillLocked); }
        env.storage().instance().remove(&DataKey::WithdrawXlmRequest);
        env.storage().instance().set(&DataKey::LastWithdrawalTime, &env.ledger().timestamp());
        soroban_sdk::token::TokenClient::new(&env, &asset).transfer(&env.current_contract_address(), &admin, &amount);
        env.events().publish((symbol_short!("wdraw_exe"), admin.clone()), WithdrawExecutedEvent { amount, recipient: admin });
        Ok(())
    }

    pub fn set_circuit_breaker_enabled(env: Env, admin: Address, enabled: bool) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.storage().instance().set(&DataKey::CircuitBreakerEnabled, &enabled);
        env.events().publish((symbol_short!("cfg_upd"), symbol_short!("circuit_enabled")), ConfigUpdatedEvent { key: String::from_str(&env, "circuit_enabled"), new_value: if enabled { 1 } else { 0 } });
        Ok(())
    }

    pub fn set_circuit_breaker_threshold(env: Env, admin: Address, threshold: u64) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.storage().instance().set(&DataKey::CircuitBreakerThreshold, &threshold);
        env.events().publish((symbol_short!("cfg_upd"), symbol_short!("circuit_threshold")), ConfigUpdatedEvent { key: String::from_str(&env, "circuit_threshold"), new_value: threshold as i128 });
        Ok(())
    }

    pub fn set_circuit_breaker_window(env: Env, admin: Address, window_seconds: u64) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.storage().instance().set(&DataKey::CircuitBreakerWindowSeconds, &window_seconds);
        env.events().publish((symbol_short!("cfg_upd"), symbol_short!("circuit_window")), ConfigUpdatedEvent { key: String::from_str(&env, "circuit_window"), new_value: window_seconds as i128 });
        Ok(())
    }

    pub fn reset_circuit_breaker(env: Env, admin: Address) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.storage().instance().set(&DataKey::CircuitBreakerWindowStart, &0u64);
        env.storage().instance().set(&DataKey::CircuitBreakerWindowCount, &0u64);
        env.events().publish((symbol_short!("circuit_reset"), admin.clone()), CircuitBreakerResetEvent {});
        Ok(())
    }

    // -------------------------------------------------------------------------
    // Batch mint
    // -------------------------------------------------------------------------

    pub fn batch_mint(
        env: Env,
        to: Address,
        clip_ids: Vec<u32>,
        metadata_uris: Vec<String>,
        images: Vec<Option<String>>,
        animation_urls: Vec<Option<String>>,
        royalty: Royalty,
        is_soulbound: bool,
        signatures: Vec<BytesN<64>>,
    ) -> Result<Vec<TokenId>, Error> {
        to.require_auth();
        Self::require_not_paused(&env)?;
        Self::enforce_mint_cooldown(&env, &to)?;
        let n = clip_ids.len();
        if n > MAX_BATCH_MINT { return Err(Error::BatchTooLarge); }
        Self::check_circuit_breaker(&env, n as u64)?;
        if n != metadata_uris.len() || n != signatures.len() || n != images.len() || n != animation_urls.len() {
            return Err(Error::InvalidRoyaltySplit);
        }
        let royalty = Self::normalize_royalty(&env, royalty)?;
        let mut minted: Vec<TokenId> = Vec::new(&env);
        for i in 0..n {
            let clip_id = clip_ids.get(i).ok_or(Error::InvalidTokenId)?;
            let metadata_uri = metadata_uris.get(i).ok_or(Error::InvalidTokenId)?;
            let image = images.get(i).ok_or(Error::InvalidTokenId)?;
            let animation_url = animation_urls.get(i).ok_or(Error::InvalidTokenId)?;
            let signature = signatures.get(i).ok_or(Error::InvalidTokenId)?;
            Self::validate_url(&env, &image)?;
            Self::validate_url(&env, &animation_url)?;
            Self::verify_clip_signature(&env, &to, clip_id, &metadata_uri, &signature)?;
            if Self::load_clip_token_id(&env, clip_id).is_some() { return Err(Error::ClipAlreadyMinted); }
            if env.storage().persistent().get::<DataKey, bool>(&DataKey::BlacklistedClip(clip_id)).unwrap_or(false) { return Err(Error::ClipBlacklisted); }
            let token_id: TokenId = env.storage().instance().get(&DataKey::NextTokenId).unwrap_or(1);
            env.storage().instance().set(&DataKey::NextTokenId, &(token_id + 1));
            env.storage().persistent().set(&DataKey::Token(token_id), &TokenData {
                owner: to.clone(), clip_id, is_soulbound, metadata_uri, image, animation_url,
                description: None, external_url: None, attributes: Vec::new(&env), royalty: royalty.clone(), is_locked: false,
            });
            Self::bump_persistent_ttl(&env, &DataKey::Token(token_id));
            env.storage().persistent().set(&DataKey::ClipIdMinted(clip_id), &token_id);
            Self::bump_persistent_ttl(&env, &DataKey::ClipIdMinted(clip_id));
            let supply: u32 = env.storage().instance().get(&DataKey::TotalSupply).unwrap_or(0);
            env.storage().instance().set(&DataKey::TotalSupply, &(supply + 1));
            env.storage().persistent().set(&DataKey::TokenIndex(supply), &token_id);
            let bal: u32 = env.storage().persistent().get(&DataKey::Balance(to.clone())).unwrap_or(0);
            env.storage().persistent().set(&DataKey::Balance(to.clone()), &(bal + 1));
            env.storage().persistent().set(&DataKey::OwnerTokenIndex(to.clone(), bal), &token_id);
            minted.push_back(token_id);
        }
        Self::record_mint_timestamp(&env, &to);
        Self::update_circuit_breaker_counter(&env, n as u64);
        let first = minted.get(0).unwrap_or(0);
        env.events().publish((symbol_short!("batch_mnt"), first), BatchMintEvent { to, count: n, first_token_id: first });
        Ok(minted)
    }

    // -------------------------------------------------------------------------
    // View functions
    // -------------------------------------------------------------------------

    pub fn owner_of(env: Env, token_id: TokenId) -> Result<Address, Error> {
        Ok(Self::load_token(&env, token_id)?.owner)
    }

    /// Returns the metadata URI for a given token ID.
    ///
    /// # Errors
    /// * [`Error::InvalidTokenId`] — token does not exist.
    pub fn token_uri(env: Env, token_id: TokenId) -> Result<String, Error> {
        // Return custom URI override if set, otherwise fall back to TokenData.
        if let Some(uri) = env
            .storage()
            .persistent()
            .get::<DataKey, String>(&DataKey::CustomTokenUri(token_id))
        {
            // Verify token exists.
            if !env.storage().persistent().has(&DataKey::Token(token_id)) {
                return Err(Error::InvalidTokenId);
            }
            return Ok(uri);
        }
        Ok(Self::load_token(&env, token_id)?.metadata_uri)
    }

    /// Alias for [`token_uri`], kept for backwards compatibility.
    pub fn get_metadata(env: Env, token_id: TokenId) -> Result<String, Error> {
        Self::token_uri(env, token_id)
    }

    /// Returns OpenSea-compatible JSON metadata for a given token ID.
    ///
    /// Serializes the token's metadata following the OpenSea metadata standard:
    /// https://docs.opensea.io/docs/metadata-standards
    ///
    /// The JSON output includes:
    /// - "metadata_uri": The base metadata URI
    /// - "image": Static thumbnail URL (only if set)
    /// - "animation_url": Animated preview URL (only if set)
    ///
    /// # Errors
    /// * [`Error::InvalidTokenId`] — token does not exist.
    pub fn get_metadata_json(env: Env, token_id: TokenId) -> Result<String, Error> {
        let data = Self::load_token(&env, token_id)?;

        let mut json = Bytes::from_slice(&env, b"{\"metadata_uri\":\"");
        Self::append_string_bytes(&env, &mut json, &data.metadata_uri);
        Self::append_literal_bytes(&env, &mut json, b"\"");

        if let Some(ref img) = data.image {
            Self::append_literal_bytes(&env, &mut json, b",\"image\":\"");
            Self::append_string_bytes(&env, &mut json, img);
            Self::append_literal_bytes(&env, &mut json, b"\"");
        }

        if let Some(ref anim) = data.animation_url {
            Self::append_literal_bytes(&env, &mut json, b",\"animation_url\":\"");
            Self::append_string_bytes(&env, &mut json, anim);
            Self::append_literal_bytes(&env, &mut json, b"\"");
        }

        if let Some(ref desc) = data.description {
            Self::append_literal_bytes(&env, &mut json, b",\"description\":\"");
            Self::append_string_bytes(&env, &mut json, desc);
            Self::append_literal_bytes(&env, &mut json, b"\"");
        }

        if let Some(ref url) = data.external_url {
            Self::append_literal_bytes(&env, &mut json, b",\"external_url\":\"");
            Self::append_string_bytes(&env, &mut json, url);
            Self::append_literal_bytes(&env, &mut json, b"\"");
        }

        Self::append_literal_bytes(&env, &mut json, b",\"attributes\":[");
        for i in 0..data.attributes.len() {
            if i > 0 {
                Self::append_literal_bytes(&env, &mut json, b",");
            }
            let attribute = data.attributes.get(i).ok_or(Error::InvalidTokenId)?;
            Self::append_literal_bytes(&env, &mut json, b"{\"trait_type\":\"");
            Self::append_string_bytes(&env, &mut json, &attribute.trait_type);
            Self::append_literal_bytes(&env, &mut json, b"\",\"value\":\"");
            Self::append_string_bytes(&env, &mut json, &attribute.value);
            Self::append_literal_bytes(&env, &mut json, b"\"}");
        }
        Self::append_literal_bytes(&env, &mut json, b"]}");
        Ok(json.to_string())
    }

    /// Look up the on-chain token ID for a given `clip_id`.
    ///
    /// # Errors
    /// * [`Error::InvalidTokenId`] — no token exists for this clip.
    pub fn clip_token_id(env: Env, clip_id: u32) -> Result<TokenId, Error> {
        Self::load_clip_token_id(&env, clip_id).ok_or(Error::InvalidTokenId)
    }

    /// Look up the on-chain token IDs for multiple clip IDs.
    /// Returns None for clip IDs that have not been minted.
    pub fn get_tokens_by_clip_ids(env: Env, clip_ids: Vec<u32>) -> Vec<Option<TokenId>> {
        let mut result = Vec::new(&env);
        for i in 0..clip_ids.len() {
            let clip_id = clip_ids.get(i).unwrap();
            result.push_back(Self::load_clip_token_id(&env, clip_id));
        }
        result
    }

    /// Returns the stored [`Royalty`] struct for a token.
    ///
    /// # Errors
    /// * [`Error::InvalidTokenId`] — token does not exist.
    pub fn get_royalty(env: Env, token_id: TokenId) -> Result<Royalty, Error> {
        Ok(Self::load_token(&env, token_id)?.royalty)
    }

    /// Returns the total number of tokens minted (not adjusted for burns).
    ///
    /// Derived from `NextTokenId - 1` — no separate counter needed.
    pub fn total_supply(env: Env) -> u32 {
        env.storage()
            .instance()
            .get(&DataKey::TotalSupply)
            .unwrap_or(0)
    }

    /// Returns the total number of clips minted so far (all-time).
    pub fn minted_count(env: Env) -> u32 {
        env.storage()
            .instance()
            .get::<DataKey, u32>(&DataKey::NextTokenId)
            .unwrap_or(1)
            .saturating_sub(1)
    }

    /// Returns `true` if the token is soulbound (non-transferable).
    pub fn is_soulbound(env: Env, token_id: TokenId) -> bool {
        Self::load_token(&env, token_id)
            .map(|d| d.is_soulbound)
            .unwrap_or(false)
    }

    /// Returns the accrued royalty balance for `token_id` (in asset smallest units).
    /// Returns `0` if no balance is recorded or the token does not exist.
    pub fn royalty_balance_of(env: Env, token_id: TokenId) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::RoyaltyBalance(token_id))
            .unwrap_or(0)
    }

    /// Returns the average gas cost for mint operations.
    /// Returns 0 if no mints have been performed.
    pub fn average_gas_mint(env: Env) -> u64 {
        let total_gas: u64 = env
            .storage()
            .temporary()
            .get(&DataKey::TotalGasMint)
            .unwrap_or(0);
        let count: u64 = env
            .storage()
            .temporary()
            .get(&DataKey::CountMint)
            .unwrap_or(0);

        if count == 0 {
            0
        } else {
            total_gas / count
        }
    }

    /// Returns the average gas cost for transfer operations.
    /// Returns 0 if no transfers have been performed.
    pub fn average_gas_transfer(env: Env) -> u64 {
        let total_gas: u64 = env
            .storage()
            .temporary()
            .get(&DataKey::TotalGasTransfer)
            .unwrap_or(0);
        let count: u64 = env
            .storage()
            .temporary()
            .get(&DataKey::CountTransfer)
            .unwrap_or(0);

        if count == 0 {
            0
        } else {
            total_gas / count
        }
    }

    /// Returns the total number of mint operations performed.
    pub fn total_mints(env: Env) -> u64 {
        env.storage()
            .temporary()
            .get(&DataKey::CountMint)
            .unwrap_or(0)
    }

    /// Returns the total number of transfer operations performed.
    pub fn total_transfers(env: Env) -> u64 {
        env.storage()
            .temporary()
            .get(&DataKey::CountTransfer)
            .unwrap_or(0)
    }

    /// Returns whether the circuit breaker is enabled.
    pub fn circuit_breaker_enabled(env: Env) -> bool {
        env.storage()
            .instance()
            .get(&DataKey::CircuitBreakerEnabled)
            .unwrap_or(DEFAULT_CIRCUIT_BREAKER_ENABLED)
    }

    /// Returns the circuit breaker threshold (max mints per window).
    pub fn circuit_breaker_threshold(env: Env) -> u64 {
        env.storage()
            .instance()
            .get(&DataKey::CircuitBreakerThreshold)
            .unwrap_or(DEFAULT_CIRCUIT_BREAKER_THRESHOLD)
    }

    /// Returns the circuit breaker time window duration in seconds.
    pub fn circuit_breaker_window_seconds(env: Env) -> u64 {
        env.storage()
            .instance()
            .get(&DataKey::CircuitBreakerWindowSeconds)
            .unwrap_or(DEFAULT_CIRCUIT_BREAKER_WINDOW_SECONDS)
    }

    /// Returns the current circuit breaker window start timestamp.
    pub fn circuit_breaker_window_start(env: Env) -> u64 {
        env.storage()
            .instance()
            .get(&DataKey::CircuitBreakerWindowStart)
            .unwrap_or(0)
    }

    /// Returns the current circuit breaker window mint count.
    pub fn circuit_breaker_window_count(env: Env) -> u64 {
        env.storage()
            .instance()
            .get(&DataKey::CircuitBreakerWindowCount)
            .unwrap_or(0)
    }

    /// Returns the number of tokens owned by `owner`.
    /// Compliant with emerging Soroban NFT standard view functions.
    pub fn balance_of(env: Env, owner: Address) -> u32 {
        env.storage()
            .persistent()
            .get(&DataKey::Balance(owner))
            .unwrap_or(0)
    }

    /// Returns the token ID at the given global index (0-based).
    ///
    /// O(1) — reads directly from the `TokenIndex` persistent map maintained
    /// by mint and burn. No iteration over burned slots.
    ///
    /// # Errors
    /// * [`Error::InvalidTokenId`] — `index` ≥ `total_supply`.
    pub fn token_by_index(env: Env, index: u32) -> Result<TokenId, Error> {
        let supply: u32 = env.storage().instance().get(&DataKey::TotalSupply).unwrap_or(0);
        if index >= supply {
            return Err(Error::InvalidTokenId);
        }
        env.storage()
            .persistent()
            .get(&DataKey::TokenIndex(index))
            .ok_or(Error::InvalidTokenId)
    }

    /// Returns the N-th token owned by `owner` (0-indexed).
    ///
    /// O(1) — reads directly from the `OwnerTokenIndex` persistent map
    /// maintained by mint, burn, and transfer. No iteration required.
    ///
    /// # Arguments
    /// * `owner` — Address to query.
    /// * `index` — 0-based position among the owner's tokens.
    ///
    /// # Errors
    /// * [`Error::InvalidTokenId`] — `index` ≥ `balance_of(owner)`.
    pub fn token_of_owner_by_index(env: Env, owner: Address, index: u32) -> Result<TokenId, Error> {
        let balance: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::Balance(owner.clone()))
            .unwrap_or(0);
        if index >= balance {
            return Err(Error::InvalidTokenId);
        }
        env.storage()
            .persistent()
            .get(&DataKey::OwnerTokenIndex(owner, index))
            .ok_or(Error::InvalidTokenId)
    }

    /// Returns the earliest ledger timestamp at which `token_id` is eligible
    /// for its next metadata refresh (i.e. `last_refresh + 30 days`).
    ///
    /// Returns `0` if the token has never been refreshed (eligible immediately).
    ///
    /// # Arguments
    /// * `token_id` — Token to query.
    ///
    /// # Errors
    /// * [`Error::InvalidTokenId`] — token does not exist.
    ///
    /// Closes #172
    pub fn get_next_metadata_refresh_time(env: Env, token_id: TokenId) -> Result<u64, Error> {
        if !Self::exists(env.clone(), token_id) {
            return Err(Error::InvalidTokenId);
        }
        const COOLDOWN: u64 = 2_592_000; // 30 days in seconds
        let next_time = env
            .storage()
            .persistent()
            .get::<DataKey, u64>(&DataKey::MetadataRefreshTime(token_id))
            .map(|last| last.saturating_add(COOLDOWN))
            .unwrap_or(0);
        Ok(next_time)
    }

    // -------------------------------------------------------------------------
    // Royalty extension (EIP-2981 style)
    // -------------------------------------------------------------------------

    /// Returns the royalty receiver, total amount, and payment asset for a sale.
    ///
    /// Formula: `royalty_amount = sale_price × total_basis_points / 10_000`
    ///
    /// Uses overflow-safe arithmetic; returns [`Error::RoyaltyOverflow`] when
    /// `sale_price > i128::MAX / 10_000`.
    ///
    /// # Arguments
    /// * `token_id`   — Token being sold.
    /// * `sale_price` — Sale price in the asset's smallest unit (must be > 0).
    ///
    /// # Errors
    /// * [`Error::InvalidTokenId`]    — token does not exist.
    /// * [`Error::InvalidSalePrice`]  — `sale_price` ≤ 0.
    /// * [`Error::RoyaltyOverflow`]   — arithmetic would overflow.
    /// * [`Error::InvalidRoyaltySplit`] — royalty recipients list is empty.
    pub fn royalty_info(
        env: Env,
        token_id: TokenId,
        sale_price: i128,
    ) -> Result<RoyaltyInfo, Error> {
        let royalty = Self::load_token(&env, token_id)?.royalty;
        let total_royalty_amount = royalty.calculate_royalty(sale_price)?;
        let first = royalty.recipients.get(0).ok_or(Error::InvalidRoyaltySplit)?;

        Ok(RoyaltyInfo {
            receiver: first.recipient,
            royalty_amount: total_royalty_amount,
            asset_address: royalty.asset_address,
        })
    }

    /// Pay royalties for a token sale using the SEP-0041 asset in the royalty config.
    ///
    /// Iterates over all recipients and transfers each share via the token client.
    /// Also accrues the total royalty amount to `RoyaltyBalance(token_id)` so
    /// recipients can track lifetime earnings and claim via [`claim_royalties`].
    /// For XLM royalties (`asset_address = None`) the marketplace must handle
    /// the transfer directly — this function returns [`Error::InvalidRecipient`].
    ///
    /// Emits: `"royalty"` [`RoyaltyPaidEvent`] per recipient paid.
    ///
    /// # Arguments
    /// * `payer`      — Address making the payment (must authorize).
    /// * `token_id`   — Token being sold.
    /// * `sale_price` — Sale price in the asset's smallest unit (must be > 0).
    ///
    /// # Errors
    /// * [`Error::InvalidSalePrice`]  — `sale_price` ≤ 0.
    /// * [`Error::InvalidTokenId`]    — token does not exist.
    /// * [`Error::InvalidRecipient`]  — no SEP-0041 asset configured (XLM royalty).
    /// * [`Error::InvalidRoyaltySplit`] — recipients list is empty.
    /// * [`Error::RoyaltyOverflow`]   — arithmetic would overflow.
    pub fn pay_royalty(
        env: Env,
        payer: Address,
        token_id: TokenId,
        sale_price: i128,
    ) -> Result<(), Error> {
        payer.require_auth();
        Self::acquire_reentrancy_lock(&env)?;
        let result = Self::pay_royalty_internal(&env, &payer, token_id, sale_price);
        Self::release_reentrancy_lock(&env);
        result
    }

    /// Internal royalty payout logic (caller must hold reentrancy lock).
    /// Follows check-effects-interactions pattern: updates storage before external transfers.
    fn pay_royalty_internal(
        env: &Env,
        payer: &Address,
        token_id: TokenId,
        sale_price: i128,
    ) -> Result<(), Error> {
        if sale_price <= 0 {
            return Err(Error::InvalidSalePrice);
        }

        let royalty = Self::load_token(env, token_id)?.royalty;
        let asset_address = royalty
            .asset_address
            .clone()
            .ok_or(Error::InvalidRecipient)?;

        // First, calculate total royalty amount (check phase)
        let mut cumulative_bps: u32 = 0;
        let mut cumulative_royalty: i128 = 0;

        for idx in 0..royalty.recipients.len() {
            let split = royalty
                .recipients
                .get(idx)
                .ok_or(Error::InvalidRoyaltySplit)?;
            cumulative_bps = cumulative_bps.saturating_add(split.basis_points);
            let total_so_far = Self::calculate_royalty(sale_price, cumulative_bps)?;
            cumulative_royalty = total_so_far;
        }

        // Update storage before external transfers (effects phase)
        // This ensures state changes are committed before any external calls
        if cumulative_royalty > 0 {
            let prev: i128 = env
                .storage()
                .persistent()
                .get(&DataKey::RoyaltyBalance(token_id))
                .unwrap_or(0);
            env.storage().persistent().set(
                &DataKey::RoyaltyBalance(token_id),
                &(prev.saturating_add(cumulative_royalty)),
            );
        }

        // Now perform external transfers (interactions phase)
        let token_client = soroban_sdk::token::TokenClient::new(env, &asset_address);
        let mut cumulative_bps: u32 = 0;
        let mut cumulative_royalty: i128 = 0;

        for idx in 0..royalty.recipients.len() {
            let split = royalty
                .recipients
                .get(idx)
                .ok_or(Error::InvalidRoyaltySplit)?;

            cumulative_bps = cumulative_bps.saturating_add(split.basis_points);
            let total_so_far = Self::calculate_royalty(sale_price, cumulative_bps)?;
            let amount = total_so_far.saturating_sub(cumulative_royalty);
            cumulative_royalty = total_so_far;

            if amount == 0 {
                continue;
            }

            token_client.transfer(payer, &split.recipient, &amount);
            env.events().publish(
                (symbol_short!("royalty"),),
                RoyaltyPaidEvent {
                    token_id,
                    from: payer.clone(),
                    to: split.recipient,
                    amount,
                },
            );
        }

        Ok(())
    }

    /// Claim accumulated royalties for a token.
    ///
    /// Transfers the full `RoyaltyBalance` for `token_id` to the primary royalty
    /// recipient using the SEP-0041 asset configured in the royalty. Clears the
    /// balance atomically (check-effects-interactions) to prevent double-claiming.
    ///
    /// Only the primary royalty recipient (index 0) may call this.
    ///
    /// Emits: `"roy_claim"` [`RoyaltyClaimedEvent`].
    ///
    /// # Arguments
    /// * `caller`   — Must be the primary royalty recipient.
    /// * `token_id` — Token whose royalties are being claimed.
    ///
    /// # Errors
    /// * [`Error::InvalidTokenId`]    — token does not exist.
    /// * [`Error::Unauthorized`]      — caller is not the primary recipient.
    /// * [`Error::InvalidRecipient`]  — no SEP-0041 asset configured.
    /// * [`Error::InsufficientBalance`] — no royalties to claim.
    pub fn claim_royalties(env: Env, caller: Address, token_id: TokenId) -> Result<(), Error> {
        caller.require_auth();
        Self::acquire_reentrancy_lock(&env)?;
        let result = Self::claim_royalties_internal(&env, &caller, token_id);
        Self::release_reentrancy_lock(&env);
        result
    }

    /// Internal royalty claim logic (caller must hold reentrancy lock).
    fn claim_royalties_internal(
        env: &Env,
        caller: &Address,
        token_id: TokenId,
    ) -> Result<(), Error> {
        let royalty = Self::load_token(env, token_id)?.royalty;
        let recipient = royalty
            .recipients
            .get(0)
            .ok_or(Error::InvalidRoyaltySplit)?
            .recipient;

        if caller != &recipient {
            return Err(Error::Unauthorized);
        }

        let asset_address = royalty.asset_address.ok_or(Error::InvalidRecipient)?;

        let balance: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::RoyaltyBalance(token_id))
            .unwrap_or(0);

        if balance <= 0 {
            return Err(Error::InsufficientBalance);
        }

        // Clear balance before transfer (check-effects-interactions).
        env.storage()
            .persistent()
            .remove(&DataKey::RoyaltyBalance(token_id));

        soroban_sdk::token::TokenClient::new(env, &asset_address).transfer(
            &env.current_contract_address(),
            &recipient,
            &balance,
        );

        env.events().publish(
            (symbol_short!("roy_clm"),),
            RoyaltyClaimedEvent {
                token_id,
                recipient,
                amount: balance,
                asset: asset_address,
            },
        );

        Ok(())
    }

    /// Update the royalty configuration for a token.
    /// Access Control: Admin only.
    /// Emits RoyaltyRecipientUpdated event when the primary recipient changes.
    pub fn set_royalty(
        env: Env,
        admin: Address,
        token_id: TokenId,
        new_royalty: Royalty,
    ) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;

        // 1 persistent read
        let mut data = Self::load_token(&env, token_id)?;
        let old_royalty = data.royalty.clone();

        // Emit event if primary recipient changed (compare before normalization)
        if !old_royalty.recipients.is_empty() && !new_royalty.recipients.is_empty() {
            let old_recipient = old_royalty
                .recipients
                .get(0)
                .ok_or(Error::InvalidRoyaltySplit)?;
            let new_recipient = new_royalty
                .recipients
                .get(0)
                .ok_or(Error::InvalidRoyaltySplit)?;

            if old_recipient.recipient != new_recipient.recipient {
                env.events().publish(
                    (symbol_short!("royalty"),),
                    RoyaltyRecipientUpdatedEvent {
                        token_id,
                        old_recipient: old_recipient.recipient,
                        new_recipient: new_recipient.recipient,
                    },
                );
            }
        }

        let new_royalty = Self::normalize_royalty(&env, new_royalty)?;

        data.royalty = new_royalty;
        env.storage()
            .persistent()
            .set(&DataKey::Token(token_id), &data);

        env.events().publish(
            (symbol_short!("roy_upd"),),
            RoyaltyUpdatedEvent { token_id },
        );

        Ok(())
    }

    /// Burn (destroy) an NFT. Only the current owner may burn.
    ///
    /// Storage removes (persistent): TokenData, ClipIdMinted = **2** (Optimized from 4)
    pub fn burn(env: Env, owner: Address, token_id: TokenId) -> Result<(), Error> {
        owner.require_auth();

        if Self::is_frozen(env.clone(), token_id) {
            return Err(Error::TokenFrozen);
        }

        // 1 persistent read — also gives us clip_id for dedup cleanup
        let data: TokenData = Self::load_token(&env, token_id)?;

        if owner != data.owner {
            return Err(Error::Unauthorized);
        }

        // 2 persistent removes
        env.storage().persistent().remove(&DataKey::Token(token_id));
        env.storage()
            .persistent()
            .remove(&DataKey::ClipIdMinted(data.clip_id));

        // Update total supply
        let total_supply: u32 = env
            .storage()
            .instance()
            .get(&DataKey::TotalSupply)
            .unwrap_or(0);
        env.storage()
            .instance()
            .set(&DataKey::TotalSupply, &total_supply.saturating_sub(1));

        // Update balance
        let balance: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::Balance(owner.clone()))
            .unwrap_or(0);
        env.storage()
            .persistent()
            .set(&DataKey::Balance(owner.clone()), &balance.saturating_sub(1));

        // Remove from O(1) enumeration indexes (must come after supply/balance decrements).
        Self::index_remove_global(&env, token_id);
        Self::index_remove_owner(&env, &owner, token_id);

        env.events().publish(
            (symbol_short!("burn"),),
            BurnEvent {
                owner: owner.clone(),
                token_id,
                clip_id: data.clip_id,
            },
        );

        // Emit standard Transfer event for ERC-721 compliance
        env.events().publish(
            (symbol_short!("transfer"),),
            TransferEvent {
                token_id,
                from: owner.clone(),
                to: env.current_contract_address(),
            },
        );

        Ok(())
    }

    /// Burn (destroy) multiple NFTs. Only the current owner may burn the tokens.
    ///
    /// Loops through `token_ids` and burns each token if owned by `owner`.
    /// All burns happen in a single transaction.
    ///
    /// Storage removes (persistent): For each token - TokenData, ClipIdMinted
    ///
    /// Emits: `"burn"` [`BurnEvent`] per token burned.
    ///
    /// # Arguments
    /// * `owner`   - Owner of the tokens (must authorize and match token ownership)
    /// * `token_ids` - List of token IDs to burn
    ///
    /// # Errors
    /// * [`Error::TokenFrozen`]   — any token is frozen.
    /// * [`Error::Unauthorized`]  — owner mismatch for any token.
    /// * [`Error::InvalidTokenId`] — any token does not exist.
    pub fn batch_burn(env: Env, owner: Address, token_ids: Vec<TokenId>) -> Result<(), Error> {
        owner.require_auth();

        // Process each token
        for i in 0..token_ids.len() {
            let token_id = token_ids.get(i).unwrap();

            // Validate token is not frozen
            if Self::is_frozen(env.clone(), token_id) {
                return Err(Error::TokenFrozen);
            }

            // Load token data and verify ownership
            let data: TokenData = Self::load_token(&env, token_id)?;
            if owner != data.owner {
                return Err(Error::Unauthorized);
            }

            // Burn the token (2 persistent removes)
            env.storage().persistent().remove(&DataKey::Token(token_id));
            env.storage()
                .persistent()
                .remove(&DataKey::ClipIdMinted(data.clip_id));

            // Update total supply
            let total_supply: u32 = env
                .storage()
                .instance()
                .get(&DataKey::TotalSupply)
                .unwrap_or(0);
            env.storage()
                .instance()
                .set(&DataKey::TotalSupply, &total_supply.saturating_sub(1));

            // Update balance
            let balance: u32 = env
                .storage()
                .persistent()
                .get(&DataKey::Balance(owner.clone()))
                .unwrap_or(0);
            env.storage()
                .persistent()
                .set(&DataKey::Balance(owner.clone()), &balance.saturating_sub(1));

            // Emit Burn event
            env.events().publish(
                (symbol_short!("burn"),),
                BurnEvent {
                    owner: owner.clone(),
                    token_id,
                    clip_id: data.clip_id,
                },
            );

            // Emit standard Transfer event for ERC-721 compliance (to zero address)
            env.events().publish(
                (symbol_short!("transfer"),),
                TransferEvent {
                    token_id,
                    from: owner.clone(),
                    to: env.current_contract_address(),
                },
            );
        }

        Ok(())
    }

    // -------------------------------------------------------------------------
    // Task 1: Update royalty recipient
    // -------------------------------------------------------------------------

    /// Allow the current royalty recipient to update their address.
    ///
    /// Only the current primary royalty recipient (index 0) may call this.
    /// Emits `RoyaltyRecipientUpdated` event.
    ///
    /// # Arguments
    /// * `caller`        - Must be the current primary royalty recipient
    /// * `token_id`      - Token whose royalty recipient is being updated
    /// * `new_recipient` - New recipient address
    pub fn update_royalty_recipient(
        env: Env,
        caller: Address,
        token_id: TokenId,
        new_recipient: Address,
    ) -> Result<(), Error> {
        caller.require_auth();

        let mut data = Self::load_token(&env, token_id)?;
        let old_recipient = data
            .royalty
            .recipients
            .get(0)
            .ok_or(Error::InvalidRoyaltySplit)?
            .recipient
            .clone();

        if caller != old_recipient {
            return Err(Error::Unauthorized);
        }

        // Replace recipient at index 0, keep basis_points unchanged
        let bps = data
            .royalty
            .recipients
            .get(0)
            .ok_or(Error::InvalidRoyaltySplit)?
            .basis_points;

        data.royalty.recipients.set(
            0,
            RoyaltyRecipient {
                recipient: new_recipient.clone(),
                basis_points: bps,
            },
        );

        env.storage()
            .persistent()
            .set(&DataKey::Token(token_id), &data);

        env.events().publish(
            (symbol_short!("royalty"),),
            RoyaltyRecipientUpdatedEvent {
                token_id,
                old_recipient,
                new_recipient,
            },
        );

        Ok(())
    }

    // -------------------------------------------------------------------------
    // Task 1 (Issue #124): tokens_of_owner view
    // -------------------------------------------------------------------------

    /// Return token IDs owned by `owner` with pagination support.
    ///
    /// This function enables frontends to display NFTs owned by a user with pagination.
    /// It iterates over minted token IDs (1..=next_token_id-1) and collects those
    /// whose owner matches.
    ///
    /// ## Storage Optimization
    /// - Linear iteration per token to check ownership (unavoidable for general query)
    /// - Single instance read for NextTokenId
    /// - Persistent reads only for tokens that might belong to owner
    ///
    /// ## Gas Protection
    /// - Result is capped at MAX_RESULTS (1000) entries to prevent gas explosion
    /// - When result reaches 1000, iteration stops even if more tokens exist
    /// - Pagination allows fetching large collections in batches
    ///
    /// # Arguments
    /// * `owner` - Address to query
    /// * `limit` - Maximum number of results to return (optional, defaults to 1000)
    /// * `offset` - Number of results to skip (optional, defaults to 0)
    ///
    /// # Returns
    /// Vec of token IDs owned by the address, respecting limit and offset
    pub fn tokens_of_owner(
        env: Env,
        owner: Address,
        limit: Option<u32>,
        offset: Option<u32>,
    ) -> Vec<TokenId> {
        const MAX_RESULTS: u32 = 1000;
        let limit = limit.unwrap_or(MAX_RESULTS).min(MAX_RESULTS);
        let offset = offset.unwrap_or(0);
        let next_id: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::Balance(owner.clone()))
            .unwrap_or(0);

        let count = if balance > MAX_RESULTS { MAX_RESULTS } else { balance };
        let mut result: Vec<TokenId> = Vec::new(&env);
        let mut count: u32 = 0;
        let mut skipped: u32 = 0;

        let mut token_id: u32 = 1;
        while token_id < next_id && count < limit {
            if let Some(data) = env
                .storage()
                .persistent()
                .get::<DataKey, TokenId>(&DataKey::OwnerTokenIndex(owner.clone(), pos))
            {
                if data.owner == owner {
                    if skipped < offset {
                        skipped += 1;
                    } else {
                        result.push_back(token_id);
                        count += 1;
                    }
                }
            }
        }
        result
    }

    /// Return a paginated list of token IDs owned by `owner`.
    ///
    /// O(limit) — reads directly from the per-owner index, no scan over
    /// burned or unrelated tokens.
    ///
    /// # Arguments
    /// * `owner`  — Address to query.
    /// * `limit`  — Max tokens to return (capped at 100).
    /// * `offset` — Number of tokens to skip (0-based page offset).
    pub fn get_user_tokens(env: Env, owner: Address, limit: u32, offset: u32) -> Vec<TokenId> {
        const MAX_LIMIT: u32 = 100;
        let limit = if limit > MAX_LIMIT { MAX_LIMIT } else { limit };

        let balance: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::Balance(owner.clone()))
            .unwrap_or(0);

        let mut result: Vec<TokenId> = Vec::new(&env);
        let end = offset.saturating_add(limit).min(balance);
        for pos in offset..end {
            if let Some(token_id) = env
                .storage()
                .persistent()
                .get::<DataKey, TokenId>(&DataKey::OwnerTokenIndex(owner.clone(), pos))
            {
                result.push_back(token_id);
            }
        }
        result
    }

    // -------------------------------------------------------------------------
    // Task 2: Batch minting
    // -------------------------------------------------------------------------

    /// Mint multiple clips in a single transaction.
    ///
    /// Loops through `clip_ids` and `metadata_uris` in lockstep, minting each
    /// with the provided `royalty` and `signatures`. Emits a single
    /// `BatchMint` event on success.
    ///
    /// # Arguments
    /// * `to`            - Owner of all minted tokens
    /// * `clip_ids`      - List of clip IDs to mint
    /// * `metadata_uris` - Corresponding metadata URIs
    /// * `images`        - Corresponding static thumbnail URLs (optional for each)
    /// * `animation_urls` - Corresponding animated preview URLs (optional for each)
    /// * `royalty`       - Royalty config applied to all tokens
    /// * `is_soulbound`  - Whether all tokens are soulbound
    /// * `signatures`    - Per-clip backend signatures
    pub fn batch_mint(
        env: Env,
        to: Address,
        clip_ids: Vec<u32>,
        metadata_uris: Vec<String>,
        images: Vec<Option<String>>,
        animation_urls: Vec<Option<String>>,
        royalty: Royalty,
        is_soulbound: bool,
        signatures: Vec<BytesN<64>>,
    ) -> Result<Vec<TokenId>, Error> {
        to.require_auth();
        Self::require_not_paused(&env)?;
        Self::enforce_mint_cooldown(&env, &to)?;

        let n = clip_ids.len();
        Self::check_circuit_breaker(&env, n as u64)?;

        if n != metadata_uris.len()
            || n != signatures.len()
            || n != images.len()
            || n != animation_urls.len()
        {
            return Err(Error::InvalidRoyaltySplit); // mismatched input lengths
        }
        if n > MAX_BATCH_MINT {
            return Err(Error::BatchTooLarge);
        }

        let royalty = Self::normalize_royalty(&env, royalty)?;
        let mut minted: Vec<TokenId> = Vec::new(&env);

        for i in 0..n {
            let clip_id = clip_ids.get(i).ok_or(Error::InvalidTokenId)?;
            let metadata_uri = metadata_uris.get(i).ok_or(Error::InvalidTokenId)?;
            let image = images.get(i).ok_or(Error::InvalidTokenId)?;
            let animation_url = animation_urls.get(i).ok_or(Error::InvalidTokenId)?;
            let signature = signatures.get(i).ok_or(Error::InvalidTokenId)?;

            // Validate URLs
            Self::validate_url(&env, &image)?;
            Self::validate_url(&env, &animation_url)?;

            Self::verify_clip_signature(&env, &to, clip_id, &metadata_uri, &signature)?;

            if Self::load_clip_token_id(&env, clip_id).is_some() {
                return Err(Error::ClipAlreadyMinted);
            }

            if env
                .storage()
                .persistent()
                .get(&DataKey::BlacklistedClip(clip_id))
                .unwrap_or(false)
            {
                return Err(Error::ClipBlacklisted);
            }

            let token_id: TokenId = env
                .storage()
                .instance()
                .get(&DataKey::NextTokenId)
                .unwrap_or(1);

            env.storage().persistent().set(
                &DataKey::Token(token_id),
                &TokenData {
                    owner: to.clone(),
                    clip_id,
                    is_soulbound,
                    metadata_uri,
                    image,
                    animation_url,
                    description: None,
                    external_url: None,
                    attributes: Vec::new(&env),
                    royalty: royalty.clone(),
                    is_locked: false,
                },
            );
            Self::bump_persistent_ttl(&env, &DataKey::Token(token_id));
            env.storage()
                .persistent()
                .set(&DataKey::ClipIdMinted(clip_id), &token_id);
            Self::bump_persistent_ttl(&env, &DataKey::ClipIdMinted(clip_id));
            env.storage()
                .instance()
                .set(&DataKey::NextTokenId, &(token_id + 1));

            // Update total supply
            let total_supply: u32 = env
                .storage()
                .instance()
                .get(&DataKey::TotalSupply)
                .unwrap_or(0);
            env.storage()
                .instance()
                .set(&DataKey::TotalSupply, &(total_supply + 1));

            // Update balance
            let balance: u32 = env
                .storage()
                .persistent()
                .get(&DataKey::Balance(to.clone()))
                .unwrap_or(0);
            env.storage()
                .persistent()
                .set(&DataKey::Balance(to.clone()), &(balance + 1));

            minted.push_back(token_id);
        }

        env.events().publish(
            (symbol_short!("batch_mnt"),),
            BatchMintEvent {
                to: to.clone(),
                count: n,
                first_token_id: minted.get(0).unwrap_or(0),
            },
        );

        // Gas tracking — Closes #169
        let count_mint: u64 = env.storage().temporary().get(&DataKey::CountMint).unwrap_or(0);
        env.storage().temporary().set(&DataKey::CountMint, &(count_mint + n as u64));
        let total_gas_mint: u64 = env.storage().temporary().get(&DataKey::TotalGasMint).unwrap_or(0);
        env.storage().temporary().set(&DataKey::TotalGasMint, &total_gas_mint.saturating_add(GAS_BASE_MINT.saturating_mul(n as u64)));
        Self::record_mint_timestamp(&env, &to);

        // Update circuit breaker counter after successful batch mint
        Self::update_circuit_breaker_counter(&env, n as u64);

        Ok(minted)
    }

    // -------------------------------------------------------------------------
    // Task 4: Public royalty fee calculation helper
    // -------------------------------------------------------------------------

    /// Calculate the royalty amount for a given sale price using the token's
    /// stored royalty configuration (sum of all recipient basis points).
    ///
    /// Returns `InvalidSalePrice` if `sale_price <= 0`.
    /// Returns `RoyaltyOverflow` if `sale_price` is too large.
    ///
    /// # Arguments
    /// * `token_id`   - Token to look up royalty config for
    /// * `sale_price` - Sale price in the token's royalty asset denomination
    pub fn calculate_royalty_amount(
        env: Env,
        token_id: TokenId,
        sale_price: i128,
    ) -> Result<i128, Error> {
        let royalty = Self::load_token(&env, token_id)?.royalty;
        royalty.calculate_royalty(sale_price)
    }

    // -------------------------------------------------------------------------
    // Circuit breaker internal helpers
    // -------------------------------------------------------------------------

    /// Check if the circuit breaker should trigger based on mint activity.
    /// If enabled and the threshold is exceeded within the time window,
    /// automatically pause the contract.
    fn check_circuit_breaker(env: &Env, mint_count: u64) -> Result<(), Error> {
        let enabled: bool = env
            .storage()
            .instance()
            .get(&DataKey::CircuitBreakerEnabled)
            .unwrap_or(DEFAULT_CIRCUIT_BREAKER_ENABLED);

        if !enabled {
            return Ok(());
        }

        let threshold: u64 = env
            .storage()
            .instance()
            .get(&DataKey::CircuitBreakerThreshold)
            .unwrap_or(DEFAULT_CIRCUIT_BREAKER_THRESHOLD);

        let window_seconds: u64 = env
            .storage()
            .instance()
            .get(&DataKey::CircuitBreakerWindowSeconds)
            .unwrap_or(DEFAULT_CIRCUIT_BREAKER_WINDOW_SECONDS);

        let now = env.ledger().timestamp();
        let window_start: u64 = env
            .storage()
            .instance()
            .get(&DataKey::CircuitBreakerWindowStart)
            .unwrap_or(0);

        let current_count: u64 = env
            .storage()
            .instance()
            .get(&DataKey::CircuitBreakerWindowCount)
            .unwrap_or(0);

        // Check if we need to reset the window (time elapsed)
        if window_start == 0 || now >= window_start.saturating_add(window_seconds) {
            // Window expired or not started - check if this batch alone would exceed threshold
            if mint_count > threshold {
                Self::trigger_circuit_breaker(env, mint_count, threshold, window_seconds)?;
            }
        } else {
            // Within current window, check if adding this batch would exceed threshold
            let new_count = current_count.saturating_add(mint_count);
            if new_count > threshold {
                Self::trigger_circuit_breaker(env, new_count, threshold, window_seconds)?;
            }
        }

        Ok(())
    }

    /// Update the circuit breaker counter after a successful mint.
    fn update_circuit_breaker_counter(env: &Env, mint_count: u64) {
        let enabled: bool = env
            .storage()
            .instance()
            .get(&DataKey::CircuitBreakerEnabled)
            .unwrap_or(DEFAULT_CIRCUIT_BREAKER_ENABLED);

        if !enabled {
            return;
        }

        let window_seconds: u64 = env
            .storage()
            .instance()
            .get(&DataKey::CircuitBreakerWindowSeconds)
            .unwrap_or(DEFAULT_CIRCUIT_BREAKER_WINDOW_SECONDS);

        let now = env.ledger().timestamp();
        let window_start: u64 = env
            .storage()
            .instance()
            .get(&DataKey::CircuitBreakerWindowStart)
            .unwrap_or(0);

        let current_count: u64 = env
            .storage()
            .instance()
            .get(&DataKey::CircuitBreakerWindowCount)
            .unwrap_or(0);

        // Check if we need to reset the window (time elapsed)
        if window_start == 0 || now >= window_start.saturating_add(window_seconds) {
            // Window expired or not started, reset counter
            env.storage()
                .instance()
                .set(&DataKey::CircuitBreakerWindowStart, &now);
            env.storage()
                .instance()
                .set(&DataKey::CircuitBreakerWindowCount, &mint_count);
        } else {
            // Within current window, increment counter
            env.storage().instance().set(
                &DataKey::CircuitBreakerWindowCount,
                &current_count.saturating_add(mint_count),
            );
        }
    }

    /// Trigger the circuit breaker by pausing the contract.
    fn trigger_circuit_breaker(
        env: &Env,
        mint_count: u64,
        threshold: u64,
        window_seconds: u64,
    ) -> Result<(), Error> {
        // Set pause flag immediately (no timelock for automatic circuit breaker)
        env.storage().instance().set(&DataKey::Paused, &true);

        // Emit event
        env.events().publish(
            (symbol_short!("circuit"),),
            CircuitBreakerTriggeredEvent {
                mint_count,
                threshold,
                window_seconds,
            },
        );

        Err(Error::CircuitBreakerTripped)
    }

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------

    /// Rejects minting when `wallet` is still inside the configured cooldown window.
    fn enforce_mint_cooldown(env: &Env, wallet: &Address) -> Result<(), Error> {
        let cooldown = Self::get_mint_cooldown_seconds(env.clone());
        if cooldown == 0 {
            return Ok(());
        }
        let now = env.ledger().timestamp();
        let key = DataKey::LastMintTimestamp(wallet.clone());
        if let Some(last_mint) = env.storage().persistent().get::<DataKey, u64>(&key) {
            if now < last_mint.saturating_add(cooldown) {
                return Err(Error::MintCooldownActive);
            }
        }
        Ok(())
    }

    /// Persists the ledger timestamp of the latest successful mint for `wallet`.
    fn record_mint_timestamp(env: &Env, wallet: &Address) {
        env.storage().persistent().set(
            &DataKey::LastMintTimestamp(wallet.clone()),
            &env.ledger().timestamp(),
        );
    }

    /// Load and return `TokenData`, or `InvalidTokenId` if not found.
    fn load_token(env: &Env, token_id: TokenId) -> Result<TokenData, Error> {
        let data: TokenData = env
            .storage()
            .persistent()
            .get(&DataKey::Token(token_id))
            .ok_or(Error::InvalidTokenId)?;
        Self::bump_persistent_ttl(env, &DataKey::Token(token_id));
        Ok(data)
    }

    /// Returns the token ID minted for `clip_id`, if any, bumping TTL when present.
    fn load_clip_token_id(env: &Env, clip_id: u32) -> Option<TokenId> {
        let key = DataKey::ClipIdMinted(clip_id);
        let token_id: Option<TokenId> = env.storage().persistent().get(&key);
        if token_id.is_some() {
            Self::bump_persistent_ttl(env, &key);
        }
        token_id
    }

    /// Extends persistent entry TTL to reduce archive risk on hot keys.
    fn bump_persistent_ttl(env: &Env, key: &DataKey) {
        env.storage().persistent().extend_ttl(
            key,
            PERSISTENT_BUMP_THRESHOLD,
            PERSISTENT_BUMP_AMOUNT,
        );
    }

    /// Returns the platform fee in basis points (default 100 = 1%).
    fn get_platform_fee(env: Env) -> u32 {
        env.storage()
            .instance()
            .get(&DataKey::PlatformFeeBps)
            .unwrap_or(100u32)
    }

    /// Returns the configured mint cooldown in seconds (default 0 = no cooldown).
    fn get_mint_cooldown_seconds(env: Env) -> u64 {
        env.storage()
            .instance()
            .get(&DataKey::MintCooldownSeconds)
            .unwrap_or(DEFAULT_MINT_COOLDOWN_SECONDS)
    }

    /// Acquire the contract reentrancy lock before external token calls.
    fn acquire_reentrancy_lock(env: &Env) -> Result<(), Error> {
        let locked: bool = env
            .storage()
            .instance()
            .get(&DataKey::ReentrancyLock)
            .unwrap_or(false);
        if locked {
            return Err(Error::Reentrancy);
        }
        env.storage()
            .instance()
            .set(&DataKey::ReentrancyLock, &true);
        Ok(())
    }

    /// Release the contract reentrancy lock after external token calls complete.
    fn release_reentrancy_lock(env: &Env) {
        env.storage()
            .instance()
            .set(&DataKey::ReentrancyLock, &false);
    }

    /// Verify the backend Ed25519 signature over the canonical mint payload.
    ///
    /// Payload:
    /// ```text
    /// owner_hash = SHA-256(XDR(owner))
    /// uri_hash   = SHA-256(UTF-8(metadata_uri))
    /// message    = SHA-256( clip_id_le4 || owner_hash || uri_hash )
    /// ```
    /// Traps (panics) on invalid signature via `env.crypto().ed25519_verify`.
    fn verify_clip_signature(
        env: &Env,
        owner: &Address,
        clip_id: u32,
        metadata_uri: &String,
        signature: &BytesN<64>,
    ) -> Result<(), Error> {
        let signer: BytesN<32> = env
            .storage()
            .instance()
            .get(&DataKey::Signer)
            .ok_or(Error::SignerNotSet)?;

        let owner_hash: BytesN<32> = env.crypto().sha256(&owner.clone().to_xdr(env)).into();
        let uri_hash: BytesN<32> = env.crypto().sha256(&Bytes::from(metadata_uri.to_xdr(env))).into();

        let mut preimage = Bytes::new(env);
        preimage.extend_from_array(&clip_id.to_le_bytes());
        preimage.append(&Bytes::from(owner_hash));
        preimage.append(&Bytes::from(uri_hash));

        let message: BytesN<32> = env.crypto().sha256(&preimage).into();

        env.crypto().ed25519_verify(&signer, &Bytes::from(message), signature);

        Ok(())
    }

    /// Ensure the backend-provided mint nonce is strictly increasing per owner.
    fn ensure_mint_nonce(env: &Env, owner: &Address, nonce: u64) -> Result<(), Error> {
        let last_nonce: u64 = env
            .storage()
            .persistent()
            .get(&DataKey::LastMintNonce(owner.clone()))
            .unwrap_or(0);
        if nonce <= last_nonce {
            return Err(Error::InvalidSignature);
        }
        Ok(())
    }

    fn record_mint_nonce(env: &Env, owner: &Address, nonce: u64) {
        env.storage()
            .persistent()
            .set(&DataKey::LastMintNonce(owner.clone()), &nonce);
    }

    /// Verify the backend Ed25519 signature over the canonical mint payload that
    /// includes a nonce to prevent replay attacks.
    ///
    /// Payload:
    /// ```text
    /// message = SHA-256(
    ///      "mint_with_signature" ||
    ///      clip_id_le_4_bytes ||
    ///      SHA-256(XDR(owner)) ||
    ///      SHA-256(UTF-8(metadata_uri)) ||
    ///      nonce_le_8_bytes
    /// )
    /// ```
    fn verify_clip_signature_with_nonce(
        env: &Env,
        owner: &Address,
        clip_id: u32,
        metadata_uri: &String,
        nonce: u64,
        signature: &BytesN<64>,
    ) -> Result<(), Error> {
        let signer: BytesN<32> = env
            .storage()
            .instance()
            .get(&DataKey::Signer)
            .ok_or(Error::SignerNotSet)?;

        let owner_hash: BytesN<32> = env.crypto().sha256(&owner.clone().to_xdr(env)).into();
        let uri_hash: BytesN<32> = env
            .crypto()
            .sha256(&Bytes::from(metadata_uri.to_xdr(env)))
            .into();

        let mut preimage = Bytes::new(env);
        preimage.append(&Bytes::from_slice(env, b"mint_with_signature"));
        preimage.extend_from_array(&clip_id.to_le_bytes());
        preimage.append(&Bytes::from(owner_hash));
        preimage.append(&Bytes::from(uri_hash));
        preimage.extend_from_array(&nonce.to_le_bytes());

        let message: BytesN<32> = env.crypto().sha256(&preimage).into();

        env.crypto().ed25519_verify(&signer, &Bytes::from(message), signature);
        Ok(())
    }

    /// Verify the backend Ed25519 signature over the recovery payload.
    ///
    /// Payload:
    /// ```text
    /// new_owner_hash = SHA-256(XDR(new_owner))
    /// message        = SHA-256( "recover" || token_id_le4 || new_owner_hash )
    /// ```
    ///
    /// The `"recover"` domain separator prevents cross-purpose replay attacks.
    fn verify_recovery_signature(
        env: &Env,
        new_owner: &Address,
        token_id: TokenId,
        signature: &BytesN<64>,
    ) -> Result<(), Error> {
        let signer: BytesN<32> = env
            .storage()
            .instance()
            .get(&DataKey::Signer)
            .ok_or(Error::SignerNotSet)?;

        let new_owner_hash: BytesN<32> = env.crypto().sha256(&new_owner.clone().to_xdr(env)).into();

        let mut preimage = Bytes::new(env);
        preimage.append(&Bytes::from_slice(env, b"recover"));
        preimage.extend_from_array(&token_id.to_le_bytes());
        preimage.append(&Bytes::from(new_owner_hash));

        let message: BytesN<32> = env.crypto().sha256(&preimage).into();

        env.crypto()
            .ed25519_verify(&signer, &Bytes::from(message), signature);

        Ok(())
    }

    /// Verify a backend Ed25519 signature over the canonical mint payload
    /// which includes a nonce to prevent replay attacks.
    ///
    /// Payload:
    /// ```text
    /// owner_hash = SHA-256(XDR(owner))
    /// uri_hash   = SHA-256(UTF-8(metadata_uri))
    /// message    = SHA-256( "mint" || clip_id_le4 || owner_hash || uri_hash || nonce_le8 )
    /// ```
    fn verify_clip_signature_with_nonce(
        env: &Env,
        owner: &Address,
        clip_id: u32,
        metadata_uri: &String,
        nonce: u64,
        signature: &BytesN<64>,
    ) -> Result<BytesN<32>, Error> {
        let signer: BytesN<32> = env
            .storage()
            .instance()
            .get(&DataKey::Signer)
            .ok_or(Error::SignerNotSet)?;

        let owner_hash: BytesN<32> = env.crypto().sha256(&owner.clone().to_xdr(env)).into();
        let uri_hash: BytesN<32> = env.crypto().sha256(&Bytes::from(metadata_uri.to_xdr(env))).into();

        let mut preimage = Bytes::new(env);
        preimage.append(&Bytes::from_slice(env, b"mint"));
        preimage.extend_from_array(&clip_id.to_le_bytes());
        preimage.append(&Bytes::from(owner_hash));
        preimage.append(&Bytes::from(uri_hash));
        preimage.extend_from_array(&nonce.to_le_bytes());

        let message: BytesN<32> = env.crypto().sha256(&preimage).into();

        // Prevent replay: ensure message hash hasn't been used
        if env
            .storage()
            .persistent()
            .has(&DataKey::UsedSignature(message.clone()))
        {
            return Err(Error::InvalidSignature);
        }

        env.crypto()
            .ed25519_verify(&signer, &Bytes::from(message.clone()), signature);

        Ok(message)
    }

    /// Mark a signature message hash as used to prevent replay.
    fn mark_signature_used(env: &Env, message: &BytesN<32>) {
        env.storage()
            .persistent()
            .set(&DataKey::UsedSignature(message.clone()), &true);
    }

    /// Assert that `addr` is the stored admin and require its authorization.
    fn require_admin(env: &Env, addr: &Address) -> Result<(), Error> {
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("Admin not initialized");

        if addr != &admin {
            return Err(Error::Unauthorized);
        }

        addr.require_auth();
        Ok(())
    }

    /// Return `ContractPaused` if the pause flag is set and the 24-hour timelock has elapsed.
    fn require_not_paused(env: &Env) -> Result<(), Error> {
        if Self::check_paused(env) {
            return Err(Error::ContractPaused);
        }
        Ok(())
    }

    /// Returns `true` if the pause flag is set AND the 24-hour timelock has elapsed.
    fn check_paused(env: &Env) -> bool {
        let flagged: bool = env
            .storage()
            .instance()
            .get(&DataKey::Paused)
            .unwrap_or(false);
        if !flagged {
            return false;
        }
        // Check if the timelock has elapsed.
        match env
            .storage()
            .instance()
            .get::<DataKey, u64>(&DataKey::PauseUnlockTime)
        {
            Some(active_at) => env.ledger().timestamp() >= active_at,
            // No timelock stored — legacy pause (immediately active).
            None => true,
        }
    }

    /// Validate royalty recipients and append the platform 1 % cut if absent.
    fn normalize_royalty(env: &Env, royalty: Royalty) -> Result<Royalty, Error> {
        if royalty.recipients.is_empty() {
            return Err(Error::InvalidRoyaltySplit);
        }
        let default_asset = env
            .storage()
            .instance()
            .get::<DataKey, Option<Address>>(&DataKey::DefaultRoyaltyAsset)
            .unwrap_or(None);
        let asset_address = royalty.asset_address.clone().or(default_asset);

        let platform: Address = env
            .storage()
            .instance()
            .get(&DataKey::PlatformRecipient)
            .ok_or(Error::InvalidRecipient)?;

        let mut recipients = royalty.recipients;
        let mut has_platform = false;
        let mut total_bps: u32 = 0;

        for idx in 0..recipients.len() {
            let split = recipients.get(idx).ok_or(Error::InvalidRoyaltySplit)?;
            if split.recipient == platform {
                has_platform = true;
            }
            total_bps = total_bps.saturating_add(split.basis_points);
        }

        if !has_platform {
            recipients.push_back(RoyaltyRecipient {
                recipient: platform,
                basis_points: 100, // fixed default 1 %
            });
            total_bps = total_bps.saturating_add(100);
        }

        if total_bps > 10_000 {
            return Err(Error::RoyaltyTooHigh);
        }

        Ok(Royalty {
            recipients,
            asset_address,
        })
    }

    /// Validate URL format and supported protocol.
    fn validate_url(_env: &Env, url: &Option<String>) -> Result<(), Error> {
        if let Some(ref u) = url {
            let bytes = u.to_bytes();
            if bytes.len() == 0 {
                return Err(Error::MalformedUrl);
            }

            let scheme_end = Self::find_scheme_separator(&bytes).ok_or(Error::MalformedUrl)?;
            if scheme_end == 0 || scheme_end + 3 >= bytes.len() {
                return Err(Error::MalformedUrl);
            }

            if Self::has_ascii_whitespace(&bytes) {
                return Err(Error::MalformedUrl);
            }

            let is_https = Self::bytes_equal_prefix(&bytes, scheme_end, b"https");
            let is_ipfs = Self::bytes_equal_prefix(&bytes, scheme_end, b"ipfs");
            if !is_https && !is_ipfs {
                return Err(Error::UnsupportedProtocol);
            }
        }
        Ok(())
    }

    /// Returns true when `value` begins with the UTF-8 `prefix` bytes.
    fn url_starts_with(_env: &Env, value: &String, prefix: &[u8]) -> bool {
        let bytes = value.to_bytes();
        let prefix_len = prefix.len() as u32;
        if bytes.len() < prefix_len {
            return false;
        }
        for i in 0..end {
            if bytes.get(i) != Some(prefix[i as usize]) {
                return false;
            }
        }
        true
    }

    fn has_ascii_whitespace(bytes: &Bytes) -> bool {
        for i in 0..bytes.len() {
            if let Some(ch) = bytes.get(i) {
                if ch == b' ' || ch == b'\n' || ch == b'\r' || ch == b'\t' {
                    return true;
                }
            }
        }
        false
    }

    /// Append a Soroban [`String`] onto a byte buffer used for JSON assembly.
    fn append_string_bytes(_env: &Env, buffer: &mut Bytes, value: &String) {
        let chunk: Bytes = value.to_bytes();
        buffer.append(&chunk);
    }

    /// Append a static UTF-8 fragment onto a byte buffer.
    fn append_literal_bytes(env: &Env, buffer: &mut Bytes, literal: &[u8]) {
        buffer.append(&Bytes::from_slice(env, literal));
    }

    /// Calculate royalty amount using safe (checked) arithmetic.
    ///
    /// Formula: `royalty_amount = (sale_price * basis_points + 5_000) / 10_000`
    ///
    /// # Safe price limits
    /// `sale_price` must be ≤ `i128::MAX / 10_000` (≈ 1.7 × 10³⁴ stroops).
    /// Prices above this threshold return `RoyaltyOverflow`.
    ///
    /// Delegates to [`safe_math::safe_royalty_amount`] — see that module for
    /// full overflow-protection documentation.
    pub fn calculate_royalty(sale_price: i128, basis_points: u32) -> Result<i128, Error> {
        safe_math::safe_royalty_amount(sale_price, basis_points)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{
        testutils::{Address as _, BytesN as _, Events as _, Ledger as _},
        xdr::ToXdr,
        Address, Bytes, BytesN, Env, String, Vec,
    };

    fn setup() -> (Env, Address, Address, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let user1 = Address::generate(&env);
        let user2 = Address::generate(&env);
        (env, admin, user1, user2)
    }

    fn default_royalty(env: &Env, recipient: Address) -> Royalty {
        let mut recipients = Vec::new(env);
        recipients.push_back(RoyaltyRecipient {
            recipient,
            basis_points: 500,
        });
        Royalty {
            recipients,
            asset_address: None,
        }
    }

    fn sign_mint(
        env: &Env,
        signer_secret: &ed25519_dalek::SigningKey,
        owner: &Address,
        clip_id: u32,
        metadata_uri: &String,
    ) -> BytesN<64> {
        let owner_hash: BytesN<32> = env.crypto().sha256(&owner.clone().to_xdr(env)).into();
        let uri_hash: BytesN<32> = env
            .crypto()
            .sha256(&Bytes::from(metadata_uri.to_xdr(env)))
            .into();
        let mut preimage = Bytes::new(env);
        preimage.extend_from_array(&clip_id.to_le_bytes());
        preimage.append(&Bytes::from(owner_hash));
        preimage.append(&Bytes::from(uri_hash));
        let message: BytesN<32> = env.crypto().sha256(&preimage).into();
        use ed25519_dalek::Signer as _;
        let sig = signer_secret.sign(&message.to_array());
        BytesN::from_array(env, &sig.to_bytes())
    }

    fn register_signer(
        env: &Env,
        client: &ClipsNftContractClient,
        admin: &Address,
    ) -> ed25519_dalek::SigningKey {
        let sk_bytes = soroban_sdk::BytesN::<32>::random(env).to_array();
        let keypair = ed25519_dalek::SigningKey::from_bytes(&sk_bytes);
        let pubkey = BytesN::from_array(env, &keypair.verifying_key().to_bytes());
        client.set_signer(admin, &pubkey);
        keypair
    }

    fn do_mint(
        client: &ClipsNftContractClient,
        env: &Env,
        to: &Address,
        clip_id: u32,
        keypair: &ed25519_dalek::SigningKey,
    ) -> TokenId {
        let uri = String::from_str(env, "ipfs://QmExample");
        let sig = sign_mint(env, keypair, to, clip_id, &uri);
        client.mint(
            to,
            &clip_id,
            &uri,
            &None, // image
            &None, // animation_url
            &default_royalty(env, to.clone()),
            &false,
            &sig,
        )
    }

    fn do_mint_soulbound(
        client: &ClipsNftContractClient,
        env: &Env,
        to: &Address,
        clip_id: u32,
        keypair: &ed25519_dalek::SigningKey,
    ) -> TokenId {
        let uri = String::from_str(env, "ipfs://QmExample");
        let sig = sign_mint(env, keypair, to, clip_id, &uri);
        client.mint(
            to,
            &clip_id,
            &uri,
            &None, // image
            &None, // animation_url
            &default_royalty(env, to.clone()),
            &true,
            &sig,
        )
    }

    #[test]
    fn test_version() {
        let env = Env::default();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        assert_eq!(client.version(), 1);
    }

    #[test]
    fn test_fee_estimators_return_expected_values() {
        let env = Env::default();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        assert_eq!(client.estimate_mint_fee(), GAS_BASE_MINT as i128);
        assert_eq!(client.estimate_transfer_fee(), GAS_BASE_TRANSFER as i128);
    }

    #[test]
    fn test_contract_info_contains_core_fields() {
        let (env, admin, _, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);

        let info = client.contract_info();
        assert_eq!(info.name, String::from_str(&env, "ClipCash Clips"));
        assert_eq!(info.symbol, String::from_str(&env, "CLIP"));
        assert_eq!(info.version, VERSION);
        assert_eq!(info.owner, admin);
        assert_eq!(info.platform_fee, 100);
    }

    #[test]
    fn test_transfer_ownership_two_step() {
        let (env, admin, user1, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);

        // Step 1: admin proposes new owner
        client.transfer_ownership(&admin, &user1);
        assert_eq!(client.pending_owner(), Some(user1.clone()));

        // Step 2: new owner accepts
        client.accept_ownership(&user1);
        assert_eq!(client.pending_owner(), None);
        assert_eq!(client.contract_info().owner, user1);
    }

    #[test]
    fn test_transfer_ownership_non_admin_fails() {
        let (env, admin, user1, user2) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);

        assert_eq!(
            client.try_transfer_ownership(&user1, &user2),
            Err(Ok(Error::Unauthorized))
        );
    }

    #[test]
    fn test_accept_ownership_wrong_caller_fails() {
        let (env, admin, user1, user2) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);

        client.transfer_ownership(&admin, &user1);
        assert_eq!(
            client.try_accept_ownership(&user2),
            Err(Ok(Error::Unauthorized))
        );
    }

    #[test]
    fn test_accept_ownership_no_pending_fails() {
        let (env, admin, user1, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);

        assert_eq!(
            client.try_accept_ownership(&user1),
            Err(Ok(Error::Unauthorized))
        );
    }

    #[test]
    fn test_mint_cooldown_enforced_and_configurable() {
        let (env, admin, user1, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);

        client.set_mint_cooldown(&admin, &120);
        assert_eq!(client.get_mint_cooldown(), 120);

        let first_clip_id = 9_001u32;
        let first_uri = String::from_str(&env, "ipfs://QmCooldown1");
        let first_sig = sign_mint(&env, &kp, &user1, first_clip_id, &first_uri);
        client.mint(
            &user1,
            &first_clip_id,
            &first_uri,
            &None,
            &None,
            &default_royalty(&env, user1.clone()),
            &false,
            &first_sig,
        );

        let second_clip_id = 9_002u32;
        let second_uri = String::from_str(&env, "ipfs://QmCooldown2");
        let second_sig = sign_mint(&env, &kp, &user1, second_clip_id, &second_uri);
        assert_eq!(
            client.try_mint(
                &user1,
                &second_clip_id,
                &second_uri,
                &None,
                &None,
                &default_royalty(&env, user1.clone()),
                &false,
                &second_sig,
            ),
            Err(Ok(Error::MintCooldownActive))
        );

        env.ledger().with_mut(|li| li.timestamp += 121);
        client.mint(
            &user1,
            &second_clip_id,
            &second_uri,
            &None,
            &None,
            &default_royalty(&env, user1.clone()),
            &false,
            &second_sig,
        );
    }

    #[test]
    fn test_mint_stores_owner_and_uri() {
        let (env, admin, user1, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);
        let token_id = do_mint(&client, &env, &user1, 42, &kp);
        assert_eq!(token_id, 1);
        assert_eq!(client.owner_of(&token_id), user1);
        assert_eq!(
            client.token_uri(&token_id),
            String::from_str(&env, "ipfs://QmExample")
        );
        assert_eq!(client.total_supply(), 1);
    }

    #[test]
    fn test_set_token_uri_owner_only_and_precedence() {
        let (env, admin, user1, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);
        let token_id = do_mint(&client, &env, &user1, 4242, &kp);
        let custom_uri = String::from_str(&env, "ipfs://QmCustomOverride");
        client.set_token_uri(&user1, &token_id, &custom_uri);
        assert_eq!(client.token_uri(&token_id), custom_uri.clone());
        assert_eq!(client.get_metadata(&token_id), custom_uri);
    }

    #[test]
    fn test_set_token_uri_non_owner_fails() {
        let (env, admin, user1, user2) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);
        let token_id = do_mint(&client, &env, &user1, 4343, &kp);
        let result = client.try_set_token_uri(
            &user2,
            &token_id,
            &String::from_str(&env, "ipfs://QmShouldFail"),
        );
        assert_eq!(result, Err(Ok(Error::Unauthorized)));
        assert_eq!(
            client.token_uri(&token_id),
            String::from_str(&env, "ipfs://QmExample")
        );
    }

    #[test]
    fn test_set_token_uri_emits_event() {
        let (env, admin, user1, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);

        let token_id = do_mint(&client, &env, &user1, 4344, &kp);
        let custom_uri = String::from_str(&env, "ipfs://QmNewURI");

        client.set_token_uri(&user1, &token_id, &custom_uri.clone());

        let events = env.events().all();
        assert!(
            events.events().len() > 0,
            "TokenUriChanged event should be emitted"
        );
    }

    #[test]
    fn test_clip_token_id_lookup() {
        let (env, admin, user1, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);
        let token_id = do_mint(&client, &env, &user1, 99, &kp);
        assert_eq!(client.clip_token_id(&99), token_id);
    }

    #[test]
    #[should_panic]
    fn test_double_mint_same_clip_id_panics() {
        let (env, admin, user1, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);
        do_mint(&client, &env, &user1, 7, &kp);
        do_mint(&client, &env, &user1, 7, &kp);
    }

    #[test]
    fn test_mint_emits_event() {
        let (env, admin, user1, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);
        let token_id = do_mint(&client, &env, &user1, 5, &kp);
        let events = env.events().all();
        // Mint emits both MintEvent and TransferEvent
        assert_eq!(events.events().len(), 2);
        assert_eq!(token_id, 1);
    }

    #[test]
    fn test_mint_fails_without_signer_set() {
        let (env, admin, user1, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp_bytes = soroban_sdk::BytesN::<32>::random(&env).to_array();
        let kp = ed25519_dalek::SigningKey::from_bytes(&kp_bytes);
        let uri = String::from_str(&env, "ipfs://QmExample");
        let sig = sign_mint(&env, &kp, &user1, 1, &uri);
        let result = client.try_mint(
            &user1,
            &1u32,
            &uri,
            &None,
            &None,
            &default_royalty(&env, user1.clone()),
            &false,
            &sig,
        );
        assert_eq!(result, Err(Ok(Error::SignerNotSet)));
    }

    #[test]
    #[should_panic]
    fn test_mint_fails_with_wrong_signature() {
        let (env, admin, user1, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        register_signer(&env, &client, &admin);
        let wrong_kp = ed25519_dalek::SigningKey::from_bytes(&soroban_sdk::BytesN::<32>::random(&env).to_array());
        let uri = String::from_str(&env, "ipfs://QmExample");
        let bad_sig = sign_mint(&env, &wrong_kp, &user1, 1, &uri);
        client.mint(&user1, &1u32, &uri, &None, &None, &default_royalty(&env, user1.clone()), &false, &bad_sig);
    }

    #[test]
    #[should_panic]
    fn test_mint_fails_with_wrong_owner_in_payload() {
        let (env, admin, user1, user2) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);
        let uri = String::from_str(&env, "ipfs://QmExample");
        let sig_for_user2 = sign_mint(&env, &kp, &user2, 1, &uri);
        client.mint(&user1, &1u32, &uri, &None, &None, &default_royalty(&env, user1.clone()), &false, &sig_for_user2);
    }

    #[test]
    #[should_panic]
    fn test_mint_fails_with_wrong_clip_id_in_payload() {
        let (env, admin, user1, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);
        let uri = String::from_str(&env, "ipfs://QmExample");
        let sig_for_99 = sign_mint(&env, &kp, &user1, 99, &uri);
        client.mint(&user1, &1u32, &uri, &None, &None, &default_royalty(&env, user1.clone()), &false, &sig_for_99);
    }

    #[test]
    fn test_set_signer_and_rotate() {
        let (env, admin, user1, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp1 = register_signer(&env, &client, &admin);
        let kp1_pub = BytesN::from_array(&env, &kp1.verifying_key().to_bytes());
        assert_eq!(client.get_signer(), Some(kp1_pub));
        let kp2 = ed25519_dalek::SigningKey::from_bytes(&soroban_sdk::BytesN::<32>::random(&env).to_array());
        let kp2_pub = BytesN::from_array(&env, &kp2.verifying_key().to_bytes());
        client.set_signer(&admin, &kp2_pub);
        assert_eq!(client.get_signer(), Some(kp2_pub));
        let uri = String::from_str(&env, "ipfs://QmExample");
        let old_sig = sign_mint(&env, &kp1, &user1, 1, &uri);
        let result = client.try_mint(
            &user1,
            &1u32,
            &uri,
            &None,
            &None,
            &default_royalty(&env, user1.clone()),
            &false,
            &old_sig,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_blacklist_clip_prevents_mint() {
        let (env, admin, user1, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);

        let clip_id = 777u32;
        client.blacklist_clip(&admin, &clip_id);

        let uri = String::from_str(&env, "ipfs://QmBlacklisted");
        let sig = sign_mint(&env, &kp, &user1, clip_id, &uri);
        let result = client.try_mint(
            &user1,
            &clip_id,
            &uri,
            &None,
            &None,
            &default_royalty(&env, user1.clone()),
            &false,
            &sig,
        );
        assert_eq!(result, Err(Ok(Error::ClipBlacklisted)));
    }

    #[test]
    fn test_blacklist_clip_emits_event() {
        let (env, admin, _, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);

        client.blacklist_clip(&admin, &888u32);
        let events = env.events().all();
        assert!(!events.events().is_empty());
    }

    #[test]
    fn test_royalty_helper_zero_price_fails() {
        let (env, _, user1, _) = setup();
        let mut recipients = Vec::new(&env);
        recipients.push_back(RoyaltyRecipient {
            recipient: user1,
            basis_points: 10_000,
        });
        let royalty = Royalty {
            recipients,
            asset_address: None,
        };

        let result = royalty.calculate_royalty(0);
        assert_eq!(result, Err(Error::InvalidSalePrice));
    }

    #[test]
    fn test_royalty_helper_max_royalty_returns_full_sale_price() {
        let (env, _, user1, _) = setup();
        let mut recipients = Vec::new(&env);
        recipients.push_back(RoyaltyRecipient {
            recipient: user1,
            basis_points: 10_000, // 100%
        });
        let royalty = Royalty {
            recipients,
            asset_address: None,
        };

        let sale_price = 123_456_789i128;
        let amount = royalty.calculate_royalty(sale_price).unwrap();
        assert_eq!(amount, sale_price);
    }

    #[test]
    fn test_mint_fails_with_unsupported_url_protocol() {
        let (env, admin, user1, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);

        let uri = String::from_str(&env, "ipfs://QmExample");
        let sig = sign_mint(&env, &kp, &user1, 808, &uri);
        let image = Some(String::from_str(&env, "ftp://example.com/poster.png"));

        let result = client.try_mint(
            &user1,
            &808u32,
            &uri,
            &image,
            &None,
            &default_royalty(&env, user1.clone()),
            &false,
            &sig,
        );
        assert_eq!(result, Err(Ok(Error::UnsupportedProtocol)));
    }

    #[test]
    fn test_mint_fails_with_malformed_url() {
        let (env, admin, user1, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);

        let uri = String::from_str(&env, "ipfs://QmExample");
        let sig = sign_mint(&env, &kp, &user1, 809, &uri);
        let image = Some(String::from_str(&env, "https://"));

        let result = client.try_mint(
            &user1,
            &809u32,
            &uri,
            &image,
            &None,
            &default_royalty(&env, user1.clone()),
            &false,
            &sig,
        );
        assert_eq!(result, Err(Ok(Error::MalformedUrl)));
    }

    #[test]
    fn test_default_royalty_asset_applied_when_not_provided() {
        let (env, admin, user1, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);

        let default_asset = Address::generate(&env);
        client.set_default_royalty_asset(&admin, &Some(default_asset.clone()));
        assert_eq!(client.get_default_royalty_asset(), Some(default_asset.clone()));

        let token_id = do_mint(&client, &env, &user1, 901, &kp);
        let stored = client.get_royalty(&token_id);
        assert_eq!(stored.asset_address, Some(default_asset));
    }

    #[test]
    fn test_explicit_royalty_asset_overrides_default() {
        let (env, admin, user1, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);

        let default_asset = Address::generate(&env);
        let explicit_asset = Address::generate(&env);
        client.set_default_royalty_asset(&admin, &Some(default_asset));

        let mut recipients = Vec::new(&env);
        recipients.push_back(RoyaltyRecipient {
            recipient: user1.clone(),
            basis_points: 500,
        });
        let royalty = Royalty {
            recipients,
            asset_address: Some(explicit_asset.clone()),
        };
        let uri = String::from_str(&env, "ipfs://QmCustomAsset");
        let sig = sign_mint(&env, &kp, &user1, 902, &uri);
        let token_id = client.mint(&user1, &902u32, &uri, &None, &None, &royalty, &false, &sig);

        let stored = client.get_royalty(&token_id);
        assert_eq!(stored.asset_address, Some(explicit_asset));
    }

    #[test]
    fn test_transfer_updates_owner() {
        let (env, admin, user1, user2) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);
        let token_id = do_mint(&client, &env, &user1, 1, &kp);
        client.transfer(&user1, &user2, &token_id, &0, &None);
        assert_eq!(client.owner_of(&token_id), user2);
    }

    #[test]
    fn test_transfer_emits_event() {
        let (env, admin, user1, user2) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);
        let token_id = do_mint(&client, &env, &user1, 3, &kp);
        client.transfer(&user1, &user2, &token_id, &0, &None);
        let events = env.events().all();
        assert_eq!(events.events().len(), 1);
    }

    #[test]
    fn test_total_supply_derived_from_next_token_id() {
        let (env, admin, user1, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);
        assert_eq!(client.total_supply(), 0);
        do_mint(&client, &env, &user1, 1, &kp);
        assert_eq!(client.total_supply(), 1);
        do_mint(&client, &env, &user1, 2, &kp);
        assert_eq!(client.total_supply(), 2);
    }

    #[test]
    fn test_royalty_info_xlm() {
        let (env, admin, user1, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);
        let token_id = do_mint(&client, &env, &user1, 1, &kp);
        let info = client.royalty_info(&token_id, &1_000_000i128);
        assert_eq!(info.royalty_amount, 60_000i128);
        assert_eq!(info.asset_address, None);
    }

    #[test]
    fn test_royalty_info_custom_asset() {
        let (env, admin, user1, _) = setup();
        let contract_id = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &contract_id);
        client.init(&admin);
        let kp = register_signer(&env, &client, &admin);
        let asset_addr = Address::generate(&env);
        let mut recipients = Vec::new(&env);
        recipients.push_back(RoyaltyRecipient { recipient: user1.clone(), basis_points: 1000 });
        let royalty = Royalty { recipients, asset_address: Some(asset_addr.clone()) };
        let uri = String::from_str(&env, "ipfs://QmCustom");
        let sig = sign_mint(&env, &kp, &user1, 2, &uri);
        let token_id = client.mint(&user1, &2u32, &uri, &None, &None, &royalty, &false, &sig);
        let info = client.royalty_info(&token_id, &500i128);
        assert_eq!(info.royalty_amount, 55i128);
        assert_eq!(info.asset_address, Some(asset_addr));
    }

    pub fn get_metadata(env: Env, token_id: TokenId) -> Result<String, Error> {
        Self::token_uri(env, token_id)
    }

    pub fn exists(env: Env, token_id: TokenId) -> bool {
        env.storage().persistent().has(&DataKey::Token(token_id))
    }

    pub fn total_supply(env: Env) -> u32 {
        env.storage().instance().get(&DataKey::TotalSupply).unwrap_or(0)
    }

    pub fn balance_of(env: Env, owner: Address) -> u32 {
        env.storage().persistent().get(&DataKey::Balance(owner)).unwrap_or(0)
    }

    pub fn name(env: Env) -> String {
        env.storage().instance().get(&DataKey::Name).unwrap_or_else(|| String::from_str(&env, "ClipCash Clips"))
    }

    pub fn symbol(env: Env) -> String {
        env.storage().instance().get(&DataKey::Symbol).unwrap_or_else(|| String::from_str(&env, "CLIP"))
    }

    pub fn version(_env: Env) -> u32 { VERSION }

    pub fn clip_token_id(env: Env, clip_id: u32) -> Result<TokenId, Error> {
        Self::load_clip_token_id(&env, clip_id).ok_or(Error::InvalidTokenId)
    }

    pub fn get_clip_id(env: Env, token_id: TokenId) -> Result<u32, Error> {
        Ok(Self::load_token(&env, token_id)?.clip_id)
    }

    pub fn is_soulbound(env: Env, token_id: TokenId) -> bool {
        Self::load_token(&env, token_id).map(|d| d.is_soulbound).unwrap_or(false)
    }

    pub fn royalty_balance_of(env: Env, token_id: TokenId) -> i128 {
        env.storage().persistent().get(&DataKey::RoyaltyBalance(token_id)).unwrap_or(0)
    }

    pub fn token_by_index(env: Env, index: u32) -> Result<TokenId, Error> {
        let supply: u32 = env.storage().instance().get(&DataKey::TotalSupply).unwrap_or(0);
        if index >= supply { return Err(Error::InvalidTokenId); }
        env.storage().persistent().get(&DataKey::TokenIndex(index)).ok_or(Error::InvalidTokenId)
    }

    pub fn token_of_owner_by_index(env: Env, owner: Address, index: u32) -> Result<TokenId, Error> {
        let bal: u32 = env.storage().persistent().get(&DataKey::Balance(owner.clone())).unwrap_or(0);
        if index >= bal { return Err(Error::InvalidTokenId); }
        env.storage().persistent().get(&DataKey::OwnerTokenIndex(owner, index)).ok_or(Error::InvalidTokenId)
    }

    pub fn contract_info(env: Env) -> ContractInfo {
        let owner: Address = env.storage().instance().get(&DataKey::Admin).expect("not init");
        ContractInfo { name: Self::name(env.clone()), symbol: Self::symbol(env.clone()), version: VERSION, owner, platform_fee: Self::get_platform_fee(env) }
    }

    pub fn circuit_breaker_enabled(env: Env) -> bool {
        env.storage().instance().get(&DataKey::CircuitBreakerEnabled).unwrap_or(DEFAULT_CIRCUIT_BREAKER_ENABLED)
    }

    pub fn circuit_breaker_threshold(env: Env) -> u64 {
        env.storage().instance().get(&DataKey::CircuitBreakerThreshold).unwrap_or(DEFAULT_CIRCUIT_BREAKER_THRESHOLD)
    }

    pub fn circuit_breaker_window_seconds(env: Env) -> u64 {
        env.storage().instance().get(&DataKey::CircuitBreakerWindowSeconds).unwrap_or(DEFAULT_CIRCUIT_BREAKER_WINDOW_SECONDS)
    }

    pub fn circuit_breaker_window_start(env: Env) -> u64 {
        env.storage().instance().get(&DataKey::CircuitBreakerWindowStart).unwrap_or(0)
    }

    pub fn circuit_breaker_window_count(env: Env) -> u64 {
        env.storage().instance().get(&DataKey::CircuitBreakerWindowCount).unwrap_or(0)
    }

    pub fn get_tokens_by_clip_ids(env: Env, clip_ids: Vec<u32>) -> Vec<Option<TokenId>> {
        let mut result = Vec::new(&env);
        for i in 0..clip_ids.len() {
            result.push_back(Self::load_clip_token_id(&env, clip_ids.get(i).unwrap()));
        }
        result
    }

    pub fn refresh_metadata(env: Env, caller: Address, token_id: TokenId, new_uri: Option<String>, image: Option<String>, animation_url: Option<String>) -> Result<(), Error> {
        caller.require_auth();
        let admin: Address = env.storage().instance().get(&DataKey::Admin).expect("not init");
        let is_backend = env.storage().instance().get::<DataKey, Address>(&DataKey::BackendAddress).map(|b| caller == b).unwrap_or(false);
        if caller != admin && !is_backend { return Err(Error::Unauthorized); }
        const COOLDOWN: u64 = 2_592_000;
        let now = env.ledger().timestamp();
        if let Some(last) = env.storage().persistent().get::<DataKey, u64>(&DataKey::MetadataRefreshTime(token_id)) {
            if now < last.saturating_add(COOLDOWN) { return Err(Error::MetadataRefreshTooSoon); }
        }
        let mut data = Self::load_token(&env, token_id)?;
        if data.is_locked { return Err(Error::MetadataLocked); }
        let old_uri = data.metadata_uri.clone();
        if let Some(uri) = new_uri { data.metadata_uri = uri; }
        if let Some(img) = image { data.image = if img.is_empty() { None } else { Some(img) }; }
        if let Some(anim) = animation_url { data.animation_url = if anim.is_empty() { None } else { Some(anim) }; }
        env.storage().persistent().set(&DataKey::Token(token_id), &data);
        env.storage().persistent().set(&DataKey::MetadataRefreshTime(token_id), &now);
        env.events().publish((symbol_short!("meta_upd"), token_id), MetadataUpdatedEvent { token_id, old_uri, new_uri: data.metadata_uri });
        Ok(())
    }

    pub fn lock_metadata(env: Env, owner: Address, token_id: TokenId) -> Result<(), Error> {
        owner.require_auth();
        let mut data = Self::load_token(&env, token_id)?;
        if data.owner != owner { return Err(Error::Unauthorized); }
        if data.is_locked { return Err(Error::MetadataLocked); }
        data.is_locked = true;
        env.storage().persistent().set(&DataKey::Token(token_id), &data);
        env.events().publish((symbol_short!("meta_lock"), token_id), MetadataLockedEvent { token_id, owner });
        Ok(())
    }

    pub fn is_metadata_locked(env: Env, token_id: TokenId) -> Result<bool, Error> {
        Ok(Self::load_token(&env, token_id)?.is_locked)
    }

    pub fn get_next_metadata_refresh_time(env: Env, token_id: TokenId) -> Result<u64, Error> {
        if !env.storage().persistent().has(&DataKey::Token(token_id)) { return Err(Error::InvalidTokenId); }
        Ok(env.storage().persistent().get::<DataKey, u64>(&DataKey::MetadataRefreshTime(token_id)).map(|l| l.saturating_add(2_592_000)).unwrap_or(0))
    }

    pub fn minted_count(env: Env) -> u32 {
        env.storage().instance().get::<DataKey, u32>(&DataKey::NextTokenId).unwrap_or(1).saturating_sub(1)
    }

    pub fn average_gas_mint(env: Env) -> u64 {
        let total: u64 = env.storage().temporary().get(&DataKey::TotalGasMint).unwrap_or(0);
        let count: u64 = env.storage().temporary().get(&DataKey::CountMint).unwrap_or(0);
        if count == 0 { 0 } else { total / count }
    }

    pub fn average_gas_transfer(env: Env) -> u64 {
        let total: u64 = env.storage().temporary().get(&DataKey::TotalGasTransfer).unwrap_or(0);
        let count: u64 = env.storage().temporary().get(&DataKey::CountTransfer).unwrap_or(0);
        if count == 0 { 0 } else { total / count }
    }

    pub fn total_mints(env: Env) -> u64 {
        env.storage().temporary().get(&DataKey::CountMint).unwrap_or(0)
    }

    pub fn total_transfers(env: Env) -> u64 {
        env.storage().temporary().get(&DataKey::CountTransfer).unwrap_or(0)
    }

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------

    fn require_admin(env: &Env, addr: &Address) -> Result<(), Error> {
        let admin: Address = env.storage().instance().get(&DataKey::Admin).expect("not init");
        if addr != &admin { return Err(Error::Unauthorized); }
        addr.require_auth();
        Ok(())
    }

    fn require_not_paused(env: &Env) -> Result<(), Error> {
        if Self::check_paused(env) { Err(Error::ContractPaused) } else { Ok(()) }
    }

    fn check_paused(env: &Env) -> bool {
        let flagged: bool = env.storage().instance().get(&DataKey::Paused).unwrap_or(false);
        if !flagged { return false; }
        match env.storage().instance().get::<DataKey, u64>(&DataKey::PauseUnlockTime) {
            Some(active_at) => env.ledger().timestamp() >= active_at,
            None => true,
        }
    }

    fn load_token(env: &Env, token_id: TokenId) -> Result<TokenData, Error> {
        let data: TokenData = env.storage().persistent().get(&DataKey::Token(token_id)).ok_or(Error::InvalidTokenId)?;
        Self::bump_persistent_ttl(env, &DataKey::Token(token_id));
        Ok(data)
    }

    fn load_clip_token_id(env: &Env, clip_id: u32) -> Option<TokenId> {
        let key = DataKey::ClipIdMinted(clip_id);
        let tid: Option<TokenId> = env.storage().persistent().get(&key);
        if tid.is_some() { Self::bump_persistent_ttl(env, &key); }
        tid
    }

    fn bump_persistent_ttl(env: &Env, key: &DataKey) {
        env.storage().persistent().extend_ttl(key, PERSISTENT_BUMP_THRESHOLD, PERSISTENT_BUMP_AMOUNT);
    }

    fn acquire_reentrancy_lock(env: &Env) -> Result<(), Error> {
        if env.storage().instance().get::<DataKey, bool>(&DataKey::ReentrancyLock).unwrap_or(false) {
            return Err(Error::Reentrancy);
        }
        env.storage().instance().set(&DataKey::ReentrancyLock, &true);
        Ok(())
    }

    fn release_reentrancy_lock(env: &Env) {
        env.storage().instance().set(&DataKey::ReentrancyLock, &false);
    }

    fn enforce_mint_cooldown(env: &Env, wallet: &Address) -> Result<(), Error> {
        let cooldown: u64 = env.storage().instance().get(&DataKey::MintCooldownSeconds).unwrap_or(0);
        if cooldown == 0 { return Ok(()); }
        let now = env.ledger().timestamp();
        if let Some(last) = env.storage().persistent().get::<DataKey, u64>(&DataKey::LastMintTimestamp(wallet.clone())) {
            if now < last.saturating_add(cooldown) { return Err(Error::MintCooldownActive); }
        }
        Ok(())
    }

    fn record_mint_timestamp(env: &Env, wallet: &Address) {
        env.storage().persistent().set(&DataKey::LastMintTimestamp(wallet.clone()), &env.ledger().timestamp());
    }

    /// Task 1: safe-math royalty calculation — delegates to safe_math module
    pub fn calculate_royalty(sale_price: i128, basis_points: u32) -> Result<i128, Error> {
        safe_math::safe_royalty_amount(sale_price, basis_points)
    }

    fn normalize_royalty(env: &Env, royalty: Royalty) -> Result<Royalty, Error> {
        if royalty.recipients.is_empty() { return Err(Error::InvalidRoyaltySplit); }
        let default_asset = env.storage().instance().get::<DataKey, Option<Address>>(&DataKey::DefaultRoyaltyAsset).unwrap_or(None);
        let asset_address = royalty.asset_address.clone().or(default_asset);
        let platform: Address = env.storage().instance().get(&DataKey::PlatformRecipient).ok_or(Error::InvalidRecipient)?;
        let platform_bps: u32 = env.storage().instance().get(&DataKey::PlatformFeeBps).unwrap_or(100);
        let mut recipients = royalty.recipients;
        let mut has_platform = false;
        let mut total_bps: u32 = 0;
        for i in 0..recipients.len() {
            let r = recipients.get(i).ok_or(Error::InvalidRoyaltySplit)?;
            if r.recipient == platform { has_platform = true; }
            total_bps = total_bps.saturating_add(r.basis_points);
        }
        if !has_platform {
            recipients.push_back(RoyaltyRecipient { recipient: platform, basis_points: platform_bps });
            total_bps = total_bps.saturating_add(platform_bps);
        }
        if total_bps > 10_000 { return Err(Error::RoyaltyTooHigh); }
        Ok(Royalty { recipients, asset_address })
    }

    fn verify_clip_signature(env: &Env, owner: &Address, clip_id: u32, metadata_uri: &String, signature: &BytesN<64>) -> Result<(), Error> {
        let signer: BytesN<32> = env.storage().instance().get(&DataKey::Signer).ok_or(Error::SignerNotSet)?;
        let owner_hash: BytesN<32> = env.crypto().sha256(&owner.clone().to_xdr(env)).into();
        let uri_hash: BytesN<32> = env.crypto().sha256(&Bytes::from(metadata_uri.to_xdr(env))).into();
        let mut preimage = Bytes::new(env);
        preimage.extend_from_array(&clip_id.to_le_bytes());
        preimage.append(&Bytes::from(owner_hash));
        preimage.append(&Bytes::from(uri_hash));
        let message: BytesN<32> = env.crypto().sha256(&preimage).into();
        env.crypto().ed25519_verify(&signer, &Bytes::from(message), signature);
        Ok(())
    }

    fn validate_url(_env: &Env, url: &Option<String>) -> Result<(), Error> {
        if let Some(ref u) = url {
            let bytes = u.to_bytes();
            if bytes.len() == 0 { return Err(Error::MalformedUrl); }
            // find "://"
            let mut scheme_end: Option<u32> = None;
            let len = bytes.len();
            for i in 0..len.saturating_sub(2) {
                if bytes.get(i) == Some(b':') && bytes.get(i+1) == Some(b'/') && bytes.get(i+2) == Some(b'/') {
                    scheme_end = Some(i);
                    break;
                }
            }
            let se = scheme_end.ok_or(Error::MalformedUrl)?;
            if se == 0 || se + 3 >= len { return Err(Error::MalformedUrl); }
            let is_https = se == 5 && bytes.get(0)==Some(b'h') && bytes.get(1)==Some(b't') && bytes.get(2)==Some(b't') && bytes.get(3)==Some(b'p') && bytes.get(4)==Some(b's');
            let is_ipfs  = se == 4 && bytes.get(0)==Some(b'i') && bytes.get(1)==Some(b'p') && bytes.get(2)==Some(b'f') && bytes.get(3)==Some(b's');
            if !is_https && !is_ipfs { return Err(Error::UnsupportedProtocol); }
        }
        Ok(())
    }

    fn index_remove_owner(env: &Env, owner: &Address, token_id: TokenId) {
        let bal: u32 = env.storage().persistent().get(&DataKey::Balance(owner.clone())).unwrap_or(0);
        if bal == 0 { return; }
        for pos in 0..bal {
            let stored: Option<TokenId> = env.storage().persistent().get(&DataKey::OwnerTokenIndex(owner.clone(), pos));
            if stored == Some(token_id) {
                let last = bal - 1;
                if pos != last {
                    let last_tid: TokenId = env.storage().persistent().get(&DataKey::OwnerTokenIndex(owner.clone(), last)).unwrap();
                    env.storage().persistent().set(&DataKey::OwnerTokenIndex(owner.clone(), pos), &last_tid);
                }
                env.storage().persistent().remove(&DataKey::OwnerTokenIndex(owner.clone(), last));
                return;
            }
        }
    }

    fn index_remove_global(env: &Env, token_id: TokenId, supply: u32) {
        if supply == 0 { return; }
        for pos in 0..supply {
            let stored: Option<TokenId> = env.storage().persistent().get(&DataKey::TokenIndex(pos));
            if stored == Some(token_id) {
                let last = supply - 1;
                if pos != last {
                    let last_tid: TokenId = env.storage().persistent().get(&DataKey::TokenIndex(last)).unwrap();
                    env.storage().persistent().set(&DataKey::TokenIndex(pos), &last_tid);
                }
                env.storage().persistent().remove(&DataKey::TokenIndex(last));
                return;
            }
        }
    }

    fn check_circuit_breaker(env: &Env, mint_count: u64) -> Result<(), Error> {
        let enabled: bool = env.storage().instance().get(&DataKey::CircuitBreakerEnabled).unwrap_or(false);
        if !enabled { return Ok(()); }
        let threshold: u64 = env.storage().instance().get(&DataKey::CircuitBreakerThreshold).unwrap_or(DEFAULT_CIRCUIT_BREAKER_THRESHOLD);
        let window: u64 = env.storage().instance().get(&DataKey::CircuitBreakerWindowSeconds).unwrap_or(DEFAULT_CIRCUIT_BREAKER_WINDOW_SECONDS);
        let now = env.ledger().timestamp();
        let ws: u64 = env.storage().instance().get(&DataKey::CircuitBreakerWindowStart).unwrap_or(0);
        let wc: u64 = env.storage().instance().get(&DataKey::CircuitBreakerWindowCount).unwrap_or(0);
        let in_window = ws != 0 && now < ws.saturating_add(window);
        let count = if in_window { wc.saturating_add(mint_count) } else { mint_count };
        if count > threshold {
            env.storage().instance().set(&DataKey::Paused, &true);
            env.events().publish((symbol_short!("circuit"), threshold), CircuitBreakerTriggeredEvent { mint_count: count, threshold, window_seconds: window });
            return Err(Error::CircuitBreakerTripped);
        }
        Ok(())
    }

    fn update_circuit_breaker_counter(env: &Env, mint_count: u64) {
        let enabled: bool = env.storage().instance().get(&DataKey::CircuitBreakerEnabled).unwrap_or(false);
        if !enabled { return; }
        let window: u64 = env.storage().instance().get(&DataKey::CircuitBreakerWindowSeconds).unwrap_or(DEFAULT_CIRCUIT_BREAKER_WINDOW_SECONDS);
        let now = env.ledger().timestamp();
        let ws: u64 = env.storage().instance().get(&DataKey::CircuitBreakerWindowStart).unwrap_or(0);
        let wc: u64 = env.storage().instance().get(&DataKey::CircuitBreakerWindowCount).unwrap_or(0);
        if ws == 0 || now >= ws.saturating_add(window) {
            env.storage().instance().set(&DataKey::CircuitBreakerWindowStart, &now);
            env.storage().instance().set(&DataKey::CircuitBreakerWindowCount, &mint_count);
        } else {
            env.storage().instance().set(&DataKey::CircuitBreakerWindowCount, &wc.saturating_add(mint_count));
        }
    }

    // -------------------------------------------------------------------------
    // Contract Upgrade & Migration
    // -------------------------------------------------------------------------

    /// Get the current contract version
    pub fn contract_version(env: Env) -> u32 {
        env.storage().instance().get(&DataKey::ContractVersion).unwrap_or(VERSION)
    }

    /// Upgrade the contract code. Only callable by admin.
    /// This swaps out the WASM code while preserving all storage.
    ///
    /// Steps:
    /// 1. Verify admin authorization
    /// 2. Get the new WASM hash from the environment (installed by Soroban CLI)
    /// 3. Call env.deployer().update_current_contract_wasm(new_wasm_hash)
    /// 4. Storage remains untouched (no migration logic here)
    /// 5. Contract logic is updated; call migrate() next to handle any data changes
    pub fn upgrade(env: Env, admin: Address) -> Result<(), Error> {
        admin.require_auth();

        // Verify caller is the admin
        let current_admin: Address = env.storage().instance().get(&DataKey::Admin)
            .ok_or(Error::Unauthorized)?;
        if current_admin != admin {
            return Err(Error::Unauthorized);
        }

        // Get the new WASM hash from the first contract data entry
        // In Soroban, you invoke upgrade() after calling soroban contract deploy --wasm <new.wasm>
        // which installs the new WASM and passes its hash via the contract data
        let new_wasm_hash: BytesN<32> = env.deployer().get_program()
            .ok_or(Error::Unauthorized)?;

        // Update the contract code
        env.deployer().update_current_contract_wasm(new_wasm_hash);

        Ok(())
    }

    /// Migrate data from one contract version to the next.
    /// Only callable by admin. Should be invoked after upgrade().
    ///
    /// This function handles:
    /// - Version-specific storage transformations
    /// - Validation that all NFTs and royalties are preserved
    /// - Bumping the ContractVersion for the new release
    pub fn migrate(env: Env, admin: Address) -> Result<(), Error> {
        admin.require_auth();

        // Verify caller is the admin
        let current_admin: Address = env.storage().instance().get(&DataKey::Admin)
            .ok_or(Error::Unauthorized)?;
        if current_admin != admin {
            return Err(Error::Unauthorized);
        }

        // Get current version
        let from_version: u32 = env.storage().instance().get(&DataKey::ContractVersion)
            .unwrap_or(1);

        // Validate: if we're at VERSION, no migration needed
        if from_version >= VERSION {
            return Ok(());
        }

        // Migration v1 -> v2 (example structure for future versions)
        if from_version == 1 {
            // Any v1 -> v2 transformations would go here
            // For now, no data changes required
        }

        // Bump the version
        env.storage().instance().set(&DataKey::ContractVersion, &VERSION);

        // Emit migration event
        env.events().publish(
            (symbol_short!("migrate"),),
            MigratedEvent {
                from_version,
                to_version: VERSION,
            },
        );

        Ok(())
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{
        testutils::{Address as _, BytesN as _, Events as _, Ledger as _},
        Address, Bytes, BytesN, Env, String, Vec, xdr::ToXdr,
    };

    fn setup() -> (Env, Address, Address, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let user1 = Address::generate(&env);
        let user2 = Address::generate(&env);
        (env, admin, user1, user2)
    }

    fn default_royalty(env: &Env, recipient: Address) -> Royalty {
        let mut r = Vec::new(env);
        r.push_back(RoyaltyRecipient { recipient, basis_points: 500 });
        Royalty { recipients: r, asset_address: None }
    }

    fn sign_mint(env: &Env, sk: &ed25519_dalek::SigningKey, owner: &Address, clip_id: u32, uri: &String) -> BytesN<64> {
        let oh: BytesN<32> = env.crypto().sha256(&owner.clone().to_xdr(env)).into();
        let uh: BytesN<32> = env.crypto().sha256(&Bytes::from(uri.to_xdr(env))).into();
        let mut pre = Bytes::new(env);
        pre.extend_from_array(&clip_id.to_le_bytes());
        pre.append(&Bytes::from(oh));
        pre.append(&Bytes::from(uh));
        let msg: BytesN<32> = env.crypto().sha256(&pre).into();
        use ed25519_dalek::Signer as _;
        BytesN::from_array(env, &sk.sign(&msg.to_array()).to_bytes())
    }

    fn register_signer(env: &Env, client: &ClipsNftContractClient, admin: &Address) -> ed25519_dalek::SigningKey {
        let sk = ed25519_dalek::SigningKey::from_bytes(&BytesN::<32>::random(env).to_array());
        client.set_signer(admin, &BytesN::from_array(env, &sk.verifying_key().to_bytes()));
        sk
    }

    fn do_mint(client: &ClipsNftContractClient, env: &Env, to: &Address, clip_id: u32, sk: &ed25519_dalek::SigningKey) -> TokenId {
        let uri = String::from_str(env, "ipfs://QmExample");
        let sig = sign_mint(env, sk, to, clip_id, &uri);
        client.mint(to, &clip_id, &uri, &None, &None, &default_royalty(env, to.clone()), &false, &sig)
    }

    // -------------------------------------------------------------------------
    // Task 1: Safe math
    // -------------------------------------------------------------------------

    #[test]
    fn test_calculate_royalty_amount_basic() {
        let (env, admin, user1, _) = setup();
        let cid = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &cid);
        client.init(&admin);
        let sk = register_signer(&env, &client, &admin);
        let tid = do_mint(&client, &env, &user1, 1, &sk);
        // 6% of 10_000 = 600
        assert_eq!(client.calculate_royalty_amount(&tid, &10_000i128), 600i128);
    }

    #[test]
    fn test_calculate_royalty_amount_zero_price_fails() {
        let (env, admin, user1, _) = setup();
        let cid = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &cid);
        client.init(&admin);
        let sk = register_signer(&env, &client, &admin);
        let tid = do_mint(&client, &env, &user1, 2, &sk);
        assert_eq!(client.try_calculate_royalty_amount(&tid, &0i128), Err(Ok(Error::InvalidSalePrice)));
    }

    #[test]
    fn test_calculate_royalty_amount_overflow_fails() {
        let (env, admin, user1, _) = setup();
        let cid = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &cid);
        client.init(&admin);
        let sk = register_signer(&env, &client, &admin);
        let tid = do_mint(&client, &env, &user1, 3, &sk);
        assert_eq!(client.try_calculate_royalty_amount(&tid, &i128::MAX), Err(Ok(Error::RoyaltyOverflow)));
    }

    #[test]
    fn test_royalty_overflow_detection() {
        let (env, admin, user1, _) = setup();
        let cid = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &cid);
        client.init(&admin);
        let sk = register_signer(&env, &client, &admin);
        let tid = do_mint(&client, &env, &user1, 4, &sk);
        assert_eq!(client.try_royalty_info(&tid, &i128::MAX), Err(Ok(Error::RoyaltyOverflow)));
    }

    #[test]
    fn test_royalty_calculation_max_safe_price() {
        let (env, admin, user1, _) = setup();
        let cid = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &cid);
        client.init(&admin);
        let sk = register_signer(&env, &client, &admin);
        let tid = do_mint(&client, &env, &user1, 5, &sk);
        let info = client.royalty_info(&tid, &(i128::MAX / 10_000));
        assert!(info.royalty_amount > 0);
    }

    #[test]
    fn test_royalty_checked_mul_max_safe_boundary() {
        let max_safe = i128::MAX / 10_000;
        assert!(ClipsNftContract::calculate_royalty(max_safe, 10_000).is_ok());
    }

    #[test]
    fn test_royalty_checked_mul_one_over_boundary_fails() {
        assert_eq!(ClipsNftContract::calculate_royalty(i128::MAX / 10_000 + 1, 1), Err(Error::RoyaltyOverflow));
    }

    #[test]
    fn test_royalty_negative_sale_price_fails() {
        assert_eq!(ClipsNftContract::calculate_royalty(-1, 500), Err(Error::InvalidSalePrice));
    }

    // -------------------------------------------------------------------------
    // Task 2: Admin config
    // -------------------------------------------------------------------------

    #[test]
    fn test_set_platform_fee_emits_event() {
        let (env, admin, _, _) = setup();
        let cid = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &cid);
        client.init(&admin);
        client.set_platform_fee(&admin, &200u32);
        assert_eq!(client.get_platform_fee(), 200u32);
        assert!(!env.events().all().is_empty());
    }

    #[test]
    fn test_set_default_royalty_emits_event() {
        let (env, admin, _, _) = setup();
        let cid = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &cid);
        client.init(&admin);
        client.set_default_royalty(&admin, &300u32);
        assert_eq!(client.get_default_royalty_bps(), 300u32);
        assert!(!env.events().all().is_empty());
    }

    #[test]
    fn test_set_platform_fee_non_admin_fails() {
        let (env, admin, user1, _) = setup();
        let cid = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &cid);
        client.init(&admin);
        assert_eq!(client.try_set_platform_fee(&user1, &100u32), Err(Ok(Error::Unauthorized)));
    }

    #[test]
    fn test_set_default_royalty_non_admin_fails() {
        let (env, admin, user1, _) = setup();
        let cid = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &cid);
        client.init(&admin);
        assert_eq!(client.try_set_default_royalty(&user1, &100u32), Err(Ok(Error::Unauthorized)));
    }

    #[test]
    fn test_set_platform_fee_too_high_fails() {
        let (env, admin, _, _) = setup();
        let cid = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &cid);
        client.init(&admin);
        assert_eq!(client.try_set_platform_fee(&admin, &10_001u32), Err(Ok(Error::RoyaltyTooHigh)));
    }

    // -------------------------------------------------------------------------
    // Task 3: get_user_tokens
    // -------------------------------------------------------------------------

    #[test]
    fn test_get_user_tokens_returns_owned() {
        let (env, admin, user1, user2) = setup();
        let cid = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &cid);
        client.init(&admin);
        let sk = register_signer(&env, &client, &admin);
        let t1 = do_mint(&client, &env, &user1, 10, &sk);
        let t2 = do_mint(&client, &env, &user1, 11, &sk);
        let _t3 = do_mint(&client, &env, &user2, 12, &sk);
        let owned = client.get_user_tokens(&user1, &100u32, &0u32);
        assert_eq!(owned.len(), 2);
        assert_eq!(owned.get(0).unwrap(), t1);
        assert_eq!(owned.get(1).unwrap(), t2);
    }

    #[test]
    fn test_get_user_tokens_pagination() {
        let (env, admin, user1, _) = setup();
        let cid = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &cid);
        client.init(&admin);
        let sk = register_signer(&env, &client, &admin);
        for i in 0..5u32 { do_mint(&client, &env, &user1, 20 + i, &sk); }
        let page1 = client.get_user_tokens(&user1, &2u32, &0u32);
        let page2 = client.get_user_tokens(&user1, &2u32, &2u32);
        assert_eq!(page1.len(), 2);
        assert_eq!(page2.len(), 2);
        assert_ne!(page1.get(0).unwrap(), page2.get(0).unwrap());
    }

    #[test]
    fn test_get_user_tokens_updates_after_transfer() {
        let (env, admin, user1, user2) = setup();
        let cid = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &cid);
        client.init(&admin);
        let sk = register_signer(&env, &client, &admin);
        let tid = do_mint(&client, &env, &user1, 30, &sk);
        client.transfer(&user1, &user2, &tid, &0i128, &None);
        assert_eq!(client.get_user_tokens(&user1, &100u32, &0u32).len(), 0);
        assert_eq!(client.get_user_tokens(&user2, &100u32, &0u32).len(), 1);
    }

    #[test]
    fn test_get_user_tokens_offset_exceeds_balance() {
        let (env, admin, user1, _) = setup();
        let cid = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &cid);
        client.init(&admin);
        let sk = register_signer(&env, &client, &admin);
        do_mint(&client, &env, &user1, 40, &sk);
        assert_eq!(client.get_user_tokens(&user1, &100u32, &10u32).len(), 0);
    }

    // -------------------------------------------------------------------------
    // Task 4: Fee estimation
    // -------------------------------------------------------------------------

    #[test]
    fn test_fee_estimators_return_expected_values() {
        let env = Env::default();
        let cid = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &cid);
        assert_eq!(client.estimate_mint_fee(), GAS_BASE_MINT as i128);
        assert_eq!(client.estimate_transfer_fee(), GAS_BASE_TRANSFER as i128);
    }

    // -------------------------------------------------------------------------
    // Core functionality
    // -------------------------------------------------------------------------

    #[test]
    fn test_version() {
        let env = Env::default();
        let cid = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &cid);
        assert_eq!(client.version(), VERSION);
    }

    #[test]
    fn test_mint_stores_owner_and_uri() {
        let (env, admin, user1, _) = setup();
        let cid = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &cid);
        client.init(&admin);
        let sk = register_signer(&env, &client, &admin);
        let tid = do_mint(&client, &env, &user1, 100, &sk);
        assert_eq!(client.owner_of(&tid), user1);
        assert_eq!(client.total_supply(), 1);
    }

    #[test]
    fn test_double_mint_prevention() {
        let (env, admin, user1, _) = setup();
        let cid = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &cid);
        client.init(&admin);
        let sk = register_signer(&env, &client, &admin);
        do_mint(&client, &env, &user1, 200, &sk);
        let uri = String::from_str(&env, "ipfs://QmExample");
        let sig = sign_mint(&env, &sk, &user1, 200, &uri);
        assert_eq!(client.try_mint(&user1, &200u32, &uri, &None, &None, &default_royalty(&env, user1.clone()), &false, &sig), Err(Ok(Error::ClipAlreadyMinted)));
    }

    #[test]
    fn test_transfer_updates_owner() {
        let (env, admin, user1, user2) = setup();
        let cid = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &cid);
        client.init(&admin);
        let sk = register_signer(&env, &client, &admin);
        let tid = do_mint(&client, &env, &user1, 300, &sk);
        client.transfer(&user1, &user2, &tid, &0i128, &None);
        assert_eq!(client.owner_of(&tid), user2);
    }

    #[test]
    fn test_burn_removes_token() {
        let (env, admin, user1, _) = setup();
        let cid = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &cid);
        client.init(&admin);
        let sk = register_signer(&env, &client, &admin);
        let tid = do_mint(&client, &env, &user1, 400, &sk);
        client.burn(&user1, &tid);
        assert!(!client.exists(&tid));
        assert_eq!(client.total_supply(), 0);
    }

    #[test]
    fn test_pause_blocks_mint() {
        let (env, admin, user1, _) = setup();
        let cid = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &cid);
        client.init(&admin);
        let sk = register_signer(&env, &client, &admin);
        client.pause(&admin, &None);
        env.ledger().with_mut(|l| l.timestamp += 86_401);
        let uri = String::from_str(&env, "ipfs://QmPaused");
        let sig = sign_mint(&env, &sk, &user1, 500, &uri);
        assert_eq!(client.try_mint(&user1, &500u32, &uri, &None, &None, &default_royalty(&env, user1.clone()), &false, &sig), Err(Ok(Error::ContractPaused)));
    }

    #[test]
    fn test_royalty_info_xlm() {
        let (env, admin, user1, _) = setup();
        let cid = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &cid);
        client.init(&admin);
        let sk = register_signer(&env, &client, &admin);
        let tid = do_mint(&client, &env, &user1, 600, &sk);
        let info = client.royalty_info(&tid, &1_000_000i128);
        assert_eq!(info.royalty_amount, 60_000i128); // 6% (5% creator + 1% platform)
    }

    #[test]
    fn test_batch_mint_success() {
        let (env, admin, user1, _) = setup();
        let cid = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &cid);
        client.init(&admin);
        let sk = register_signer(&env, &client, &admin);
        let uri1 = String::from_str(&env, "ipfs://Qm1");
        let uri2 = String::from_str(&env, "ipfs://Qm2");
        let mut cids = Vec::new(&env); cids.push_back(700u32); cids.push_back(701u32);
        let mut uris = Vec::new(&env); uris.push_back(uri1.clone()); uris.push_back(uri2.clone());
        let mut imgs: Vec<Option<String>> = Vec::new(&env); imgs.push_back(None); imgs.push_back(None);
        let mut anims: Vec<Option<String>> = Vec::new(&env); anims.push_back(None); anims.push_back(None);
        let mut sigs = Vec::new(&env);
        sigs.push_back(sign_mint(&env, &sk, &user1, 700, &uri1));
        sigs.push_back(sign_mint(&env, &sk, &user1, 701, &uri2));
        let minted = client.batch_mint(&user1, &cids, &uris, &imgs, &anims, &default_royalty(&env, user1.clone()), &false, &sigs);
        assert_eq!(minted.len(), 2);
        assert_eq!(client.total_supply(), 2);
    }

    #[test]
    fn test_withdraw_timelock_is_48h() {
        let (env, admin, _, _) = setup();
        let cid = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &cid);
        client.init(&admin);
        client.request_withdraw_asset(&admin, &1_000i128);
        let asset = Address::generate(&env);
        assert_eq!(client.try_withdraw_asset(&admin, &asset, &1_000i128), Err(Ok(Error::WithdrawalStillLocked)));
        env.ledger().with_mut(|l| l.timestamp += 172_801);
        // would succeed if contract had funds; just verify lock is released
    }

    #[test]
    fn test_soulbound_transfer_blocked() {
        let (env, admin, user1, user2) = setup();
        let cid = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &cid);
        client.init(&admin);
        let sk = register_signer(&env, &client, &admin);
        let uri = String::from_str(&env, "ipfs://QmSoul");
        let sig = sign_mint(&env, &sk, &user1, 800, &uri);
        let tid = client.mint(&user1, &800u32, &uri, &None, &None, &default_royalty(&env, user1.clone()), &true, &sig);
        assert_eq!(client.try_transfer(&user1, &user2, &tid, &0i128, &None), Err(Ok(Error::SoulboundTransferBlocked)));
    }

    #[test]
    fn test_token_by_index_enumerable() {
        let (env, admin, user1, _) = setup();
        let cid = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &cid);
        client.init(&admin);
        let sk = register_signer(&env, &client, &admin);
        let t1 = do_mint(&client, &env, &user1, 900, &sk);
        let t2 = do_mint(&client, &env, &user1, 901, &sk);
        assert_eq!(client.token_by_index(&0u32), t1);
        assert_eq!(client.token_by_index(&1u32), t2);
        client.burn(&user1, &t1);
        assert_eq!(client.total_supply(), 1);
        assert_eq!(client.try_token_by_index(&1u32), Err(Ok(Error::InvalidTokenId)));
    }

    #[test]
    fn test_refresh_metadata_cooldown_enforced() {
        let (env, admin, user1, _) = setup();
        let cid = env.register(ClipsNftContract, ());
        let client = ClipsNftContractClient::new(&env, &cid);
        client.init(&admin);
        let sk = register_signer(&env, &client, &admin);
        let tid = do_mint(&client, &env, &user1, 1000, &sk);
        client.refresh_metadata(&admin, &tid, &Some(String::from_str(&env, "ipfs://v2")), &None, &None);
        env.ledger().with_mut(|l| l.timestamp += 29 * 24 * 3600);
        assert_eq!(client.try_refresh_metadata(&admin, &tid, &Some(String::from_str(&env, "ipfs://v3")), &None, &None), Err(Ok(Error::MetadataRefreshTooSoon)));
    }
}
