//! ClipCash NFT — Soroban Smart Contract
//!
//! Enables minting video clips as NFTs on the Stellar network with built-in
//! royalty support for content creators. Royalties can be paid in XLM or any
//! SEP-0041 custom Stellar asset.
//!
//! # Clip verification
//!
//! Before a clip can be minted the backend must sign a verification payload
//! with its Ed25519 private key. The contract verifies the signature on-chain
//! using `env.crypto().ed25519_verify()`.
//!
//! ## Payload format
//!
//! ```text
//! payload = SHA-256( clip_id_le_bytes || SHA-256(owner_xdr) || SHA-256(metadata_uri_bytes) )
//! ```
//!
//! # Storage layout
//!
//! | Tier       | Keys                                              |
//! |------------|---------------------------------------------------|
//! | instance   | Admin, NextTokenId, Paused, Signer, Name, Symbol, PlatformRecipient |
//! | persistent | Token(id), ClipIdMinted(clip_id), Approved(id), ApprovalForAll(owner,op), BlacklistedClip(clip_id) |
//!
//! # Privileged entrypoints (admin-only)
//!
//! ## Storage tiers used
//! - `instance`   – cheap, loaded once per tx, shared across all calls in the tx.
//!   Used for: Admin, NextTokenId, Paused, Signer.
//! - `persistent` – per-entry fee, survives ledger expiry extension.
//!   Used for: TokenData (owner+clip_id packed), Metadata, Royalty,
//!   ClipIdMinted (dedup guard).
//!
//! ## Estimated storage operations per function
//!
//! ### `mint`
//! | Op              | Tier       | Count |
//! |-----------------|------------|-------|
//! | instance read   | instance   | 4     | (Admin, NextTokenId, Paused, Signer)
//! | instance write  | instance   | 1     | (NextTokenId++)
//! | persistent read | persistent | 1     | (ClipIdMinted dedup check)
//! | persistent write| persistent | 4     | (TokenData, Metadata, Royalty, ClipIdMinted)
//! Total persistent writes: **4**
//!
//! ### `transfer`
//! | Op              | Tier       | Count |
//! |-----------------|------------|-------|
//! | instance read   | instance   | 1     | (Paused)
//! | persistent read | persistent | 1     | (TokenData — owner check)
//! | persistent write| persistent | 1     | (TokenData — new owner)
//! Total persistent writes: **1**
//!
//! ### `burn`
//! | Op              | Tier       | Count |
//! |-----------------|------------|-------|
//! | persistent read | persistent | 1     | (TokenData — owner check + clip_id)
//! | persistent remove| persistent| 4     | (TokenData, Metadata, Royalty, ClipIdMinted)
//! Total persistent removes: **4**
//!
//! ## Removed counters / indexes (vs. earlier version)
//! - `Balance(Address)` — per-address token counter removed.
//! - `TokenCount` — replaced by `next_token_id - 1`.
//! - `TokenClipId(TokenId)` — clip_id packed into `TokenData`.
//! - [`ClipsNftContract::set_signer`]
//! - [`ClipsNftContract::upgrade`]
//! - [`ClipsNftContract::pause`]
//! - [`ClipsNftContract::unpause`]
//! - [`ClipsNftContract::blacklist_clip`]
//! - [`ClipsNftContract::set_name`]
//! - [`ClipsNftContract::set_symbol`]
//! - [`ClipsNftContract::set_royalty`]

#![no_std]

pub mod safe_math;

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, symbol_short, xdr::ToXdr, Address, Bytes,
    BytesN, Env, String, Vec,
};

/// Contract version — bump on every breaking change.
pub const VERSION: u32 = 1;
pub const DEFAULT_MINT_COOLDOWN_SECONDS: u64 = 0;

// =============================================================================
// Errors
// =============================================================================

/// All error codes returned by the contract.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum Error {
    /// Caller is not authorized for this operation.
    Unauthorized = 1,
    /// Token ID does not exist.
    InvalidTokenId = 2,
    /// Clip has already been minted.
    ClipAlreadyMinted = 3,
    /// Total royalty basis points exceed 10 000 (100 %).
    RoyaltyTooHigh = 4,
    /// Royalty recipient address is invalid or missing.
    InvalidRecipient = 5,
    /// Sale price must be greater than zero.
    InvalidSalePrice = 6,
    /// Contract is paused — minting and transfers are blocked.
    ContractPaused = 7,
    /// Backend Ed25519 signature over the mint payload is invalid.
    InvalidSignature = 8,
    /// No backend signer public key has been registered yet.
    SignerNotSet = 9,
    /// Royalty split configuration is invalid.
    InvalidRoyaltySplit = 10,
    /// Token is soulbound (non-transferable).
    SoulboundTransferBlocked = 11,
    /// Royalty calculation would overflow i128.
    RoyaltyOverflow = 12,
    /// Clip ID has been blacklisted by the admin.
    ClipBlacklisted = 13,
    /// Caller is not the owner or an approved operator.
    NotAuthorizedToApprove = 14,
    /// Withdrawal is still locked (24h safety delay)
    WithdrawalStillLocked = 15,
    /// No active withdrawal request found
    NoWithdrawalRequest = 16,
    /// Batch mint request exceeds configured gas-safe limit
    BatchTooLarge = 17,
    /// Token is frozen and cannot be transferred or burned.
    TokenFrozen = 18,
    /// Insufficient balance for this operation.
    InsufficientBalance = 19,
    /// Metadata was refreshed too recently (30-day cooldown not elapsed).
    MetadataRefreshTooSoon = 20,
    /// Image URL must start with "https://" or "ipfs://".
    InvalidImageUrl = 21,
    /// Animation URL must start with "https://" or "ipfs://".
    InvalidAnimationUrl = 22,
    /// Mint attempted before wallet cooldown elapsed.
    MintCooldownActive = 23,
    /// Reentrant call detected while a guarded entrypoint is executing.
    Reentrancy = 24,
}

// =============================================================================
// Types
// =============================================================================

/// Opaque token identifier (auto-incremented u32).
pub type TokenId = u32;

/// All per-token state packed into a single persistent storage entry.
///
/// Combining owner, clip_id, metadata, and royalty into one entry reduces
/// persistent writes per mint from 4 to 2.
/// Token metadata following the OpenSea metadata standard.
/// See: https://docs.opensea.io/docs/metadata-standards
///
/// # Fields
/// * `owner` — Current owner of the token.
/// * `clip_id` — Off-chain clip identifier this token was minted for.
/// * `is_soulbound` — When `true` the token cannot be transferred (soulbound).
/// * `metadata_uri` — Metadata URI (IPFS or Arweave).
/// * `image` — Static thumbnail URL. Recommended formats: PNG, JPEG, GIF (static), SVG.
///   Max 100 MB. Must be a fully-qualified URL (https:// or ipfs://).
/// * `animation_url` — Animated preview URL. Recommended formats: GIF, MP4 (H.264), WEBM,
///   GLB/GLTF (for 3D), HTML (for interactive). Max 100 MB. Must be a fully-qualified URL.
///   Takes precedence for playback; `image` is used as the fallback thumbnail.
/// * `royalty` — Royalty configuration for secondary sales.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Attribute {
    /// OpenSea trait type (e.g. "Quality").
    pub trait_type: String,
    /// OpenSea trait value (e.g. "Gold").
    pub value: String,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenData {
    /// Current owner of the token.
    pub owner: Address,
    /// Off-chain clip identifier this token was minted for.
    pub clip_id: u32,
    /// When `true` the token cannot be transferred (soulbound).
    pub is_soulbound: bool,
    /// Metadata URI (IPFS or Arweave).
    pub metadata_uri: String,
    /// Static thumbnail URL (optional). Recommended formats: PNG, JPEG, GIF (static), SVG.
    /// Max 100 MB. Must be a fully-qualified URL (https:// or ipfs://).
    pub image: Option<String>,
    /// Animated preview URL (optional). Recommended formats: GIF, MP4, WEBM, GLB/GLTF, HTML.
    /// Max 100 MB. Must be a fully-qualified URL (https:// or ipfs://).
    /// Takes precedence for playback; `image` is used as the fallback thumbnail.
    pub animation_url: Option<String>,
    /// Optional OpenSea description.
    pub description: Option<String>,
    /// Optional OpenSea external URL.
    pub external_url: Option<String>,
    /// Optional OpenSea trait attributes.
    pub attributes: Vec<Attribute>,
    /// Royalty configuration for secondary sales.
    pub royalty: Royalty,
}

/// A single royalty split recipient.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoyaltyRecipient {
    /// Address that receives this portion of the royalty.
    pub recipient: Address,
    /// Share expressed in basis points (1 bp = 0.01 %).
    pub basis_points: u32,
}

/// Royalty configuration stored per token.
///
/// `asset_address = None` means royalties are expected in native XLM.
/// `asset_address = Some(addr)` means a SEP-0041 token at `addr`.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Royalty {
    /// Ordered list of recipients. The platform recipient (1 %) is appended
    /// automatically by [`ClipsNftContract::mint`] if not already present.
    pub recipients: Vec<RoyaltyRecipient>,
    /// Optional SEP-0041 asset contract address.
    pub asset_address: Option<Address>,
}

/// Royalty payment info returned by [`ClipsNftContract::royalty_info`].
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoyaltyInfo {
    /// Primary royalty receiver (first recipient in the split).
    pub receiver: Address,
    /// Total royalty amount in the same denomination as `sale_price`.
    pub royalty_amount: i128,
    /// `None` → pay in XLM; `Some(addr)` → pay in that SEP-0041 token.
    pub asset_address: Option<Address>,
}

/// Contract metadata and key settings for frontend bootstrap.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContractInfo {
    pub name: String,
    pub symbol: String,
    pub version: u32,
    pub owner: Address,
    pub platform_fee: u32,
}

// =============================================================================
// Storage keys
// =============================================================================

/// Typed storage keys.
///
/// Enum variants with no payload are 1-word keys (cheapest).
/// Variants with a `u32` payload are 2-word keys (minimum for per-token data).
#[contracttype]
pub enum DataKey {
    /// Contract administrator address (instance).
    Admin,
    /// Monotonically increasing token ID counter (instance).
    /// `total_supply = NextTokenId - 1`.
    NextTokenId,
    /// Pause flag (instance).
    Paused,
    /// Pause reason (instance storage)
    PauseReason,
    /// Collection name (instance storage)
    Name,
    /// Collection symbol (instance).
    Symbol,
    /// Packed owner + clip_id + metadata + royalty for a token (persistent).
    Token(TokenId),
    /// Dedup guard: clip_id → token_id (persistent).
    ClipIdMinted(u32),
    /// Custom metadata URI override per token (persistent).
    CustomTokenUri(TokenId),
    /// Ed25519 public key of the trusted backend signer (instance).
    Signer,
    /// Platform address that always receives the default 1 % royalty cut (instance).
    PlatformRecipient,
    /// Per-token approval: token_id → approved operator (persistent).
    Approved(TokenId),
    /// Track metadata update count per token (persistent storage)
    MetadataUpdateCount(TokenId),
    /// Operator approval for all: (owner, operator) -> bool
    ApprovalForAll(Address, Address),
    /// Blacklist flag for a clip_id (persistent).
    BlacklistedClip(u32),
    /// Pending XLM withdrawal request (instance storage)
    WithdrawXlmRequest,
    /// Timestamp of the last successfully executed withdrawal (instance storage)
    LastWithdrawalTime,
    /// Per-address balance (persistent).
    Balance(Address),
    /// Current total supply of tokens (instance).
    TotalSupply,
    /// Gas tracking fields (instance)
    TotalGasMint,
    CountMint,
    TotalGasTransfer,
    CountTransfer,
    /// Frozen status per token (persistent).
    Frozen(TokenId),
    /// Timestamp of the last metadata refresh per token (persistent).
    MetadataRefreshTime(TokenId),
    /// Ledger timestamp at which a scheduled pause becomes active (instance).
    PauseUnlockTime,
    /// Platform fee in basis points (instance).
    PlatformFeeBps,
    /// Default royalty in basis points (instance).
    DefaultRoyaltyBps,
    /// Accumulated royalty balance per token (persistent).
    RoyaltyBalance(TokenId),
    /// Last successful mint timestamp per wallet (persistent).
    LastMintTimestamp(Address),
    /// Required delay between mints from one wallet (instance).
    MintCooldownSeconds,
    /// Reentrancy guard for external token calls (instance).
    ReentrancyLock,
}

/// Emergency withdrawal request
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WithdrawRequest {
    pub amount: i128,
    pub unlock_time: u64,
}

/// Event emitted when a withdrawal is requested.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WithdrawRequestedEvent {
    pub amount: i128,
    pub unlock_time: u64,
}

/// Event emitted when a withdrawal is executed.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WithdrawExecutedEvent {
    pub amount: i128,
    pub recipient: Address,
}

// =============================================================================
// Events
// =============================================================================

/// Emitted when a new NFT is minted.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MintEvent {
    pub to: Address,
    pub clip_id: u32,
    pub token_id: TokenId,
    pub metadata_uri: String,
}

/// Emitted when an NFT is burned.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BurnEvent {
    pub owner: Address,
    pub token_id: TokenId,
    pub clip_id: u32,
}

/// Emitted when NFT ownership changes.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransferEvent {
    pub token_id: TokenId,
    pub from: Address,
    pub to: Address,
}

/// Event emitted when a clip ID is blacklisted.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlacklistEvent {
    pub clip_id: u32,
}

/// Emitted when an operator is approved for a specific token.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalEvent {
    pub owner: Address,
    pub operator: Address,
    pub token_id: TokenId,
}

/// Emitted when approval-for-all is set or revoked.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalForAllEvent {
    pub owner: Address,
    pub operator: Address,
    pub approved: bool,
}

/// Event emitted when royalty is paid.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoyaltyPaidEvent {
    pub token_id: TokenId,
    pub from: Address,
    pub to: Address,
    pub amount: i128,
}

/// Event emitted when royalty recipient is updated.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoyaltyRecipientUpdatedEvent {
    pub token_id: TokenId,
    pub old_recipient: Address,
    pub new_recipient: Address,
}

/// Event emitted when token URI is updated by the owner.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenUriChangedEvent {
    pub token_id: TokenId,
    pub owner: Address,
    pub new_uri: String,
}

/// Event emitted when the contract is upgraded.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpgradeEvent {
    pub new_wasm_hash: BytesN<32>,
}

/// Event emitted when multiple NFTs are batch-minted.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchMintEvent {
    pub to: Address,
    pub count: u32,
    pub first_token_id: TokenId,
}

/// Event emitted when token metadata is updated.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetadataUpdatedEvent {
    pub token_id: TokenId,
    pub old_uri: String,
    pub new_uri: String,
}

/// Emitted when an NFT is frozen.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenFrozenEvent {
    pub token_id: TokenId,
}

/// Emitted when an NFT is unfrozen.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenUnfrozenEvent {
    pub token_id: TokenId,
}

/// Emitted when the backend signer key is registered or rotated.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignerUpdatedEvent {
    pub new_pubkey: BytesN<32>,
}

/// Emitted when a token's royalty configuration is updated by the admin.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoyaltyUpdatedEvent {
    pub token_id: TokenId,
}

/// Emitted when a pause is scheduled (24-hour timelock starts).
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PauseScheduledEvent {
    /// Ledger timestamp at which the pause becomes active.
    pub active_at: u64,
}

/// Emitted when the collection name or symbol is updated.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CollectionUpdatedEvent {
    /// "name" or "symbol"
    pub field: String,
    pub new_value: String,
}

/// Emitted when a platform config value is updated.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigUpdatedEvent {
    pub key: String,
    pub new_value: u32,
}

/// Emitted when accumulated royalties are claimed.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoyaltyClaimedEvent {
    pub token_id: TokenId,
    pub recipient: Address,
    pub amount: i128,
}

/// Emitted when the contract admin is changed.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminChangedEvent {
    pub old_admin: Address,
    pub new_admin: Address,
}

/// Emitted when an NFT is burned and optional unclaimed royalties are refunded.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RefundedEvent {
    pub token_id: TokenId,
    pub recipient: Address,
    pub amount: i128,
}

/// Emerging Soroban NFT standard interface (ERC-721 adapted).
/// Documents the expected API surface for marketplace interoperability.
pub trait NftStandard {
    /// Returns how many tokens `owner` holds.
    fn balance_of(env: Env, owner: Address) -> u32;
    /// Returns the owner of `token_id`.
    fn owner_of(env: Env, token_id: TokenId) -> Result<Address, Error>;
    /// Transfers `token_id` from `from` to `to`.
    fn transfer(env: Env, from: Address, to: Address, token_id: TokenId) -> Result<(), Error>;
    /// Approves `operator` to manage `token_id` (or clears approval when `None`).
    fn approve(env: Env, caller: Address, operator: Option<Address>, token_id: TokenId) -> Result<(), Error>;
    /// Returns the per-token approved operator, if any.
    fn get_approved(env: Env, token_id: TokenId) -> Option<Address>;
    /// Grants or revokes operator rights for all tokens owned by `caller`.
    fn set_approval_for_all(env: Env, caller: Address, operator: Address, approved: bool) -> Result<(), Error>;
    /// Returns whether `operator` may manage all tokens for `owner`.
    fn is_approved_for_all(env: Env, owner: Address, operator: Address) -> bool;
    /// Returns the number of minted tokens.
    fn total_supply(env: Env) -> u32;
    /// Returns the metadata URI for `token_id`.
    fn token_uri(env: Env, token_id: TokenId) -> Result<String, Error>;
    /// Returns the collection name.
    fn name(env: Env) -> String;
    /// Returns the collection symbol.
    fn symbol(env: Env) -> String;
    /// Revokes approval for a specific token ID.
    fn revoke_approval(env: Env, token_id: TokenId) -> Result<(), Error>;
    /// Revokes approval for an operator managing all caller tokens.
    fn revoke_all_approvals(env: Env, operator: Address) -> Result<(), Error>;
    /// Destroys a token and handles optional remaining royalty refund matching criteria.
    fn burn(env: Env, token_id: TokenId, refund_royalty: bool) -> Result<(), Error>;
}

// =============================================================================
// Contract
// =============================================================================

/// ClipCash NFT contract.
#[contract]
pub struct ClipsNftContract;

#[allow(deprecated)]
/// Synthetic gas constants for tracking (approximations)
const GAS_BASE_MINT: u64 = 50_000;
const GAS_BASE_TRANSFER: u64 = 30_000;
const MAX_BATCH_MINT: u32 = 25;
const PERSISTENT_BUMP_THRESHOLD: u32 = 172_800;
const PERSISTENT_BUMP_AMOUNT: u32 = 535_680;

#[contractimpl]
impl ClipsNftContract {
    // -------------------------------------------------------------------------
    // Initialization
    // -------------------------------------------------------------------------

    /// Initialize the contract and set the admin.
    ///
    /// Can only be called once. Panics if already initialized.
    ///
    /// # Arguments
    /// * `admin` — Address that becomes the contract administrator.
    pub fn init(env: Env, admin: Address) {
        if env.storage().instance().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &admin);
        // NextTokenId starts at 1; total_supply = NextTokenId - 1
        env.storage().instance().set(&DataKey::NextTokenId, &1u32);
        env.storage().instance().set(&DataKey::Paused, &false);
        env.storage().instance().set(&DataKey::PlatformRecipient, &admin);
        env.storage()
            .instance()
            .set(&DataKey::Name, &String::from_str(&env, "ClipCash Clips"));
        env.storage()
            .instance()
            .set(&DataKey::Symbol, &String::from_str(&env, "CLIP"));
        env.storage()
            .instance()
            .set(&DataKey::MintCooldownSeconds, &DEFAULT_MINT_COOLDOWN_SECONDS);
        // Signer is not set at init — call set_signer before minting.
    }

    // -------------------------------------------------------------------------
    // Signer management  ⚠️ PRIVILEGED — admin only
    // -------------------------------------------------------------------------

    /// Register (or rotate) the backend Ed25519 public key used to verify
    /// clip ownership before minting.
    ///
    /// ⚠️ **Access Control: Admin only.**
    ///
    /// # Arguments
    /// * `admin`  — Must be the contract admin.
    /// * `pubkey` — 32-byte Ed25519 public key of the trusted backend signer.
    pub fn set_signer(env: Env, admin: Address, pubkey: BytesN<32>) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.storage().instance().set(&DataKey::Signer, &pubkey);
        env.events().publish(
            (symbol_short!("sgn_upd"),),
            SignerUpdatedEvent { new_pubkey: pubkey },
        );
        Ok(())
    }

    /// Return the currently registered backend signer public key, if any.
    pub fn get_signer(env: Env) -> Option<BytesN<32>> {
        env.storage().instance().get(&DataKey::Signer)
    }

    /// Transfer contract admin rights to a new address.
    ///
    /// ⚠️ **Access Control: current admin only.**
    ///
    /// Emits: `"adm_chg"` [`AdminChangedEvent`].
    ///
    /// # Arguments
    /// * `current_admin` — Must be the current contract admin.
    /// * `new_admin`      — Address that will become the new admin.
    ///
    /// # Errors
    /// * [`Error::Unauthorized`] — `current_admin` is not the stored admin.
    ///
    /// Closes #177
    pub fn set_admin(env: Env, current_admin: Address, new_admin: Address) -> Result<(), Error> {
        Self::require_admin(&env, &current_admin)?;
        env.storage().instance().set(&DataKey::Admin, &new_admin);
        env.events().publish(
            (symbol_short!("adm_chg"),),
            AdminChangedEvent {
                old_admin: current_admin,
                new_admin,
            },
        );
        Ok(())
    }

    // -------------------------------------------------------------------------
    // Upgradeability  ⚠️ PRIVILEGED — admin only
    // -------------------------------------------------------------------------

    /// Upgrade the contract to a new WASM implementation.
    ///
    /// ⚠️ **Access Control: Admin only.**
    ///
    /// Replaces the current contract code with the new WASM hash while
    /// preserving all instance and persistent storage.
    ///
    /// # Arguments
    /// * `admin`          — Must be the contract admin.
    /// * `new_wasm_hash` — 32-byte SHA-256 hash of the new WASM blob.
    pub fn upgrade(env: Env, admin: Address, new_wasm_hash: BytesN<32>) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.deployer().update_current_contract_wasm(new_wasm_hash.clone());
        env.events().publish(
            (symbol_short!("upgrade"),),
            UpgradeEvent { new_wasm_hash },
        );
        Ok(())
    }

    // -------------------------------------------------------------------------
    // Pausable  ⚠️ PRIVILEGED — admin only
    // -------------------------------------------------------------------------

    /// Schedule a contract pause with a 24-hour timelock.
    ///
    /// the pause becomes active 24 hours after this call. Until then, `mint`
    /// and `transfer` continue to work, giving users advance warning.
    /// Calling `pause` again while a pause is already scheduled or active
    /// resets the 24-hour window from the current time.
    ///
    /// ⚠️ **Access Control: Admin only.**
    ///
    /// Emits: `"pause_sched"` [`PauseScheduledEvent`] with the activation timestamp.
    pub fn pause(env: Env, admin: Address) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        let active_at = env.ledger().timestamp().saturating_add(86_400); // 24 hours
        env.storage().instance().set(&DataKey::PauseUnlockTime, &active_at);
        env.storage().instance().set(&DataKey::Paused, &true);
        env.events().publish(
            (symbol_short!("pse_sched"),),
            PauseScheduledEvent { active_at },
        );
        Ok(())
    }

    /// Cancel a scheduled or active pause, immediately re-enabling `mint` and `transfer`.
    ///
    /// ⚠️ **Access Control: Admin only.**
    ///
    /// Emits: `"unpaused"` event.
    pub fn unpause(env: Env, admin: Address) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.storage().instance().set(&DataKey::Paused, &false);
        env.storage().instance().remove(&DataKey::PauseUnlockTime);
        env.events().publish((symbol_short!("unpaused"),), ());
        Ok(())
    }

    /// Returns `true` if the contract is currently paused (timelock has elapsed).
    pub fn is_paused(env: Env) -> bool {
        Self::check_paused(&env)
    }

    /// Returns the timestamp at which a scheduled pause becomes active, or `None`.
    pub fn pause_active_at(env: Env) -> Option<u64> {
        env.storage().instance().get(&DataKey::PauseUnlockTime)
    }

    /// Request an emergency withdrawal of XLM (or any other token).
    /// Starts a 48-hour safety delay (timelock) before the withdrawal can be executed.
    /// Only callable by the admin.
    ///
    /// Emits `WithdrawRequested` event with amount and unlock_time.
    ///
    /// Part of Closes #78
    pub fn request_withdraw_asset(env: Env, admin: Address, amount: i128) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        if amount <= 0 {
            return Err(Error::InvalidSalePrice);
        }

        let unlock_time = env.ledger().timestamp().saturating_add(172_800); // 48 hours
        let request = WithdrawRequest { amount, unlock_time };

        env.storage().instance().set(&DataKey::WithdrawXlmRequest, &request);

        env.events().publish(
            (symbol_short!("with_req"),),
            WithdrawRequestedEvent { amount, unlock_time },
        );
        Ok(())
    }

    /// Execute a previously requested emergency withdrawal after the 24-hour safety delay.
    /// Only callable by the admin.
    ///
    /// Emits `WithdrawExecuted` event with amount and recipient.
    /// Uses check-effects-interactions pattern: clears request before transfer.
    ///
    /// Closes #78
    ///
    /// # Arguments
    /// * `admin` - Must be the contract admin
    /// * `asset` - The contract address of the asset to withdraw (e.g. native XLM)
    /// * `amount` - The amount to withdraw (must match the requested amount)
    pub fn withdraw_asset(env: Env, admin: Address, asset: Address, amount: i128) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        Self::acquire_reentrancy_lock(&env)?;
        let result = Self::withdraw_asset_internal(&env, &admin, &asset, amount);
        Self::release_reentrancy_lock(&env);
        result
    }

    /// Internal asset withdrawal (caller must hold reentrancy lock).
    fn withdraw_asset_internal(
        env: &Env,
        admin: &Address,
        asset: &Address,
        amount: i128,
    ) -> Result<(), Error> {
        let request: WithdrawRequest = env.storage().instance()
            .get(&DataKey::WithdrawXlmRequest)
            .ok_or(Error::NoWithdrawalRequest)?;

        if amount != request.amount {
            return Err(Error::Unauthorized);
        }

        if env.ledger().timestamp() < request.unlock_time {
            return Err(Error::WithdrawalStillLocked);
        }

        // Clear the request before execution to prevent double-spend if transfer fails/reenters
        env.storage().instance().remove(&DataKey::WithdrawXlmRequest);

        // Execute the transfer
        let client = soroban_sdk::token::TokenClient::new(env, asset);
        client.transfer(&env.current_contract_address(), admin, &amount);

        // Record the timestamp of this withdrawal for audit purposes
        env.storage()
            .instance()
            .set(&DataKey::LastWithdrawalTime, &env.ledger().timestamp());

        env.events().publish(
            (symbol_short!("with_exe"),),
            WithdrawExecutedEvent {
                amount,
                recipient: admin.clone(),
            },
        );

        Ok(())
    }

    /// Blacklist a clip ID, preventing it from being minted.
    /// Only callable by the admin.
    pub fn blacklist_clip(env: Env, admin: Address, clip_id: u32) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        env.storage()
            .persistent()
            .set(&DataKey::BlacklistedClip(clip_id), &true);
        env.events()
            .publish((symbol_short!("blacklist"),), BlacklistEvent { clip_id });
        Ok(())
    }

    /// Freeze an NFT so transfers and burns are blocked until unfrozen.
    ///
    /// ⚠️ **Access Control: Admin only.**
    ///
    /// Emits: `"freeze"` [`TokenFrozenEvent`].
    pub fn freeze(env: Env, admin: Address, token_id: TokenId) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        if !Self::exists(env.clone(), token_id) {
            return Err(Error::InvalidTokenId);
        }
        env.storage().persistent().set(&DataKey::Frozen(token_id), &true);
        env.events().publish((symbol_short!("freeze"),), TokenFrozenEvent { token_id });
        Ok(())
    }

    /// Unfreeze an NFT, re-enabling transfers and burning.
    /// Only callable by the admin.
    pub fn unfreeze(env: Env, admin: Address, token_id: TokenId) -> Result<(), Error> {
        Self::require_admin(&env, &admin)?;
        if !Self::exists(env.clone(), token_id) {
            return Err(Error::InvalidTokenId);
        }
        env.storage().persistent().remove(&DataKey::Frozen(token_id));
        env.events().publish((symbol_short!("unfreeze"),), TokenUnfrozenEvent { token_id });
        Ok(())
    }

    /// Returns `true` if the token is currently frozen.
    pub fn is_frozen(env: Env, token_id: TokenId) -> bool {
        env.storage().persistent().get(&DataKey::Frozen(token_id)).unwrap_or(false)
    }

    // -------------------------------------------------------------------------
    // Approval Revocations
    // -------------------------------------------------------------------------

    /// Revokes marketplace or operator approval for a specific token ID.
    pub fn revoke_approval(env: Env, token_id: TokenId) -> Result<(), Error> {
        let token_data: TokenData = env
            .storage()
            .persistent()
            .get(&DataKey::Token(token_id))
            .ok_or(Error::InvalidTokenId)?;

        token_data.owner.require_auth();

        let approval_key = DataKey::Approved(token_id);
        if env.storage().persistent().has(&approval_key) {
            env.storage().persistent().remove(&approval_key);
            
            env.events().publish(
                (symbol_short!("approval"),),
                ApprovalEvent {
                    owner: token_data.owner,
                    operator: env.current_contract_address(),
                    token_id,
                },
            );
        }
        Ok(())
    }

    /// Revokes general operator permissions for an operator managing the caller's items.
    pub fn revoke_all_approvals(env: Env, operator: Address) -> Result<(), Error> {
        operator.require_auth();

        let approval_all_key = DataKey::ApprovalForAll(env.current_contract_address(), operator.clone());
        if env.storage().persistent().has(&approval_all_key) {
            env.storage().persistent().remove(&approval_all_key);

            env.events().publish(
                (symbol_short!("app_all"),),
                ApprovalForAllEvent {
                    owner: env.current_contract_address(),
                    operator,
                    approved: false,
                },
            );
        }
        Ok(())
    }

    // -------------------------------------------------------------------------
    // Core NFT operations
    // -------------------------------------------------------------------------

    /// Destroys an NFT and optionally claims outstanding accrued royalties back to the creator.
    ///
    /// Closes #136
    pub fn burn(env: Env, token_id: TokenId, refund_royalty: bool) -> Result<(), Error> {
        let token_key = DataKey::Token(token_id);
        let token_data: TokenData = env
            .storage()
            .persistent()
            .get(&token_key)
            .ok_or(Error::InvalidTokenId)?;

        token_data.owner.require_auth();

        if Self::is_frozen(env.clone(), token_id) {
            return Err(Error::TokenFrozen);
        }

        // Handle optional royalty recovery tracking back to the primary creator asset configuration rules
        if refund_royalty {
            let royalty_key = DataKey::RoyaltyBalance(token_id);
            if env.storage().persistent().has(&royalty_key) {
                let accumulated_amount: i128 = env.storage().persistent().get(&royalty_key).unwrap_or(0);
                
                if accumulated_amount > 0 {
                    // Extract original primary creator/receiver info if existing
                    if let Some(first_recipient) = token_data.royalty.recipients.get(0) {
                        let target_creator = first_recipient.recipient;
                        
                        // Transfer out using specified contract token type structure defaults
                        if let Some(ref asset_addr) = token_data.royalty.asset_address {
                            let client = soroban_sdk::token::TokenClient::new(&env, asset_addr);
                            client.transfer(&env.current_contract_address(), &target_creator, &accumulated_amount);
                        }
                        
                        env.events().publish(
                            (symbol_short!("refunded"),),
                            RefundedEvent {
                                token_id,
                                recipient: target_creator,
                                amount: accumulated_amount,
                            },
                        );
                    }
                }
                env.storage().persistent().remove(&royalty_key);
            }
        }

        // Clean up remaining storage keys mapped to this token context
        env.storage().persistent().remove(&token_key);
        env.storage().persistent().remove(&DataKey::ClipIdMinted(token_data.clip_id));
        env.storage().persistent().remove(&DataKey::Approved(token_id));
        env.storage().persistent().remove(&DataKey::CustomTokenUri(token_id));
        env.storage().persistent().remove(&DataKey::MetadataUpdateCount(token_id));
        env.storage().persistent().remove(&DataKey::MetadataRefreshTime(token_id));

        env.events().publish(
            (symbol_short!("burn"),),
            BurnEvent {
                owner: token_data.owner,
                token_id,
                clip_id: token_data.clip_id,
            },
        );

        Ok(())
    }

    /// Internal checker helper functions mapped by your setup layers
    fn require_admin(env: &Env, admin: &Address) -> Result<(), Error> {
        let stored_admin: Address = env.storage().instance().get(&DataKey::Admin).ok_or(Error::Unauthorized)?;
        if admin != &stored_admin {
            return Err(Error::Unauthorized);
        }
        admin.require_auth();
        Ok(())
    }

    fn check_paused(env: &Env) -> bool {
        env.storage().instance().get(&DataKey::Paused).unwrap_or(false)
    }

    fn exists(env: Env, token_id: TokenId) -> bool {
        env.storage().persistent().has(&DataKey::Token(token_id))
    }

    fn acquire_reentrancy_lock(env: &Env) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::ReentrancyLock) {
            return Err(Error::Reentrancy);
        }
        env.storage().instance().set(&DataKey::ReentrancyLock, &true);
        Ok(())
    }

    fn release_reentrancy_lock(env: &Env) {
        env.storage().instance().remove(&DataKey::ReentrancyLock);
    }
}
