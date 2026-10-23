// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// @title CustodyVault
/// @notice An M-of-N vault for ETH and ERC-20 tokens with a policy layer:
///
///   1. M-of-N approvals: every withdrawal and every configuration change is a
///      proposal that needs `threshold` distinct owner approvals.
///   2. Destination allowlist: funds can only go to addresses on the list.
///   3. Per-asset rate limit: a token bucket that refills at `dailyLimit` per
///      24h and never holds more than `dailyLimit`. Unconfigured assets have a
///      limit of 0, so the default is deny.
///   4. Timelock: withdrawals of `largeThreshold` or more, and every
///      configuration change, wait `timelockDelay` after reaching M approvals.
///      Any single owner can cancel during that window.
///   5. Emergency pause: any single owner can pause withdrawals instantly;
///      unpausing needs a full M-of-N, timelocked configuration proposal.
///
/// Configuration changes are proposals whose payload is a call back into this
/// contract (`onlySelf` functions). There is no admin key and no path that
/// moves funds except `execute` on an approved withdrawal proposal.
contract CustodyVault is ReentrancyGuard {
    using SafeERC20 for IERC20;

    // ------------------------------------------------------------------
    // Types
    // ------------------------------------------------------------------

    enum Kind {
        Withdrawal,
        Config
    }

    struct Proposal {
        Kind kind;
        address asset; // address(0) = ETH. Withdrawal only.
        address to; // Withdrawal only.
        uint256 amount; // Withdrawal only.
        bytes data; // Config only: calldata for an onlySelf function.
        uint64 createdAt;
        uint64 thresholdReachedAt; // 0 until M approvals; timelock starts here
        uint64 ownerSetVersion; // proposals die when the owner set or threshold changes
        bool largeAtCreation; // Withdrawal: amount >= largeThreshold when proposed
        bool executed;
        bool cancelled;
    }

    struct AssetPolicy {
        uint128 dailyLimit; // bucket capacity and refill per 24h
        uint128 largeThreshold; // amount at or above which the timelock applies
    }

    struct Bucket {
        uint128 available;
        uint64 lastUpdate;
    }

    // ------------------------------------------------------------------
    // Constants and immutables
    // ------------------------------------------------------------------

    address public constant ETH = address(0);
    uint256 public constant MAX_OWNERS = 20;
    /// A proposal must collect M approvals within this window of being created...
    uint256 public constant APPROVAL_WINDOW = 14 days;
    /// ...and, once executable, must be executed within this window, so stale approvals cannot be used months later.
    uint256 public constant EXECUTION_WINDOW = 7 days;
    uint256 public constant MIN_TIMELOCK = 1 hours;
    uint256 public constant MAX_TIMELOCK = 30 days;

    uint256 public immutable timelockDelay;

    // ------------------------------------------------------------------
    // State
    // ------------------------------------------------------------------

    address[] internal _owners;
    mapping(address => bool) public isOwner;
    uint256 public threshold;
    /// Bumped on every owner or threshold change; invalidates open proposals.
    uint64 public ownerSetVersion;

    mapping(address => bool) public isAllowedDestination;
    mapping(address => AssetPolicy) public assetPolicy;
    mapping(address => Bucket) internal _buckets;

    bool public paused;

    Proposal[] internal _proposals;
    mapping(uint256 => mapping(address => bool)) public hasApproved;

    // ------------------------------------------------------------------
    // Events (every state change is logged; M5's audit log can consume these)
    // ------------------------------------------------------------------

    event Deposited(address indexed asset, address indexed from, uint256 amount);
    event Proposed(uint256 indexed id, Kind kind, address indexed proposer);
    event Approved(uint256 indexed id, address indexed owner, uint256 approvals);
    event Revoked(uint256 indexed id, address indexed owner, uint256 approvals);
    event ThresholdReached(uint256 indexed id, uint256 executableAt);
    event Cancelled(uint256 indexed id, address indexed owner);
    event Executed(uint256 indexed id, address indexed executor);
    event Withdrawn(uint256 indexed id, address indexed asset, address indexed to, uint256 amount);
    event Paused(address indexed by);
    event Unpaused();
    event OwnerAdded(address indexed owner);
    event OwnerRemoved(address indexed owner);
    event ThresholdChanged(uint256 threshold);
    event DestinationSet(address indexed destination, bool allowed);
    event AssetPolicySet(address indexed asset, uint256 dailyLimit, uint256 largeThreshold);

    // ------------------------------------------------------------------
    // Errors
    // ------------------------------------------------------------------

    error NotOwner();
    error NotSelf();
    error InvalidOwners();
    error InvalidThreshold();
    error InvalidTimelock();
    error IsPaused();
    error DestinationNotAllowed(address to);
    error ZeroAmount();
    error UseReceiveForEth();
    error AmountExceedsDailyLimit(uint256 amount, uint256 dailyLimit);
    error RateLimited(uint256 amount, uint256 available);
    error InsufficientVaultBalance(uint256 amount, uint256 balance);
    error UnknownProposal(uint256 id);
    error ProposalClosed(uint256 id);
    error ProposalExpired(uint256 id);
    error ProposalStale(uint256 id);
    error AlreadyApproved(uint256 id);
    error NotApproved(uint256 id);
    error NotEnoughApprovals(uint256 id, uint256 approvals, uint256 threshold);
    error TimelockActive(uint256 id, uint256 executableAt);
    error ConfigCallNotAllowed(bytes4 selector);
    error ConfigCallFailed(bytes returndata);
    error EthTransferFailed();

    // ------------------------------------------------------------------
    // Modifiers
    // ------------------------------------------------------------------

    modifier onlyOwner() {
        if (!isOwner[msg.sender]) revert NotOwner();
        _;
    }

    /// Configuration functions are reachable only through an executed Config proposal.
    modifier onlySelf() {
        if (msg.sender != address(this)) revert NotSelf();
        _;
    }

    // ------------------------------------------------------------------
    // Construction and deposits
    // ------------------------------------------------------------------

    constructor(address[] memory owners_, uint256 threshold_, uint256 timelockDelay_) {
        if (owners_.length == 0 || owners_.length > MAX_OWNERS) revert InvalidOwners();
        if (threshold_ == 0 || threshold_ > owners_.length) revert InvalidThreshold();
        if (timelockDelay_ < MIN_TIMELOCK || timelockDelay_ > MAX_TIMELOCK) revert InvalidTimelock();
        for (uint256 i = 0; i < owners_.length; i++) {
            address o = owners_[i];
            if (o == address(0) || o == address(this) || isOwner[o]) revert InvalidOwners();
            isOwner[o] = true;
            _owners.push(o);
            emit OwnerAdded(o);
        }
        threshold = threshold_;
        timelockDelay = timelockDelay_;
        emit ThresholdChanged(threshold_);
    }

    receive() external payable {
        emit Deposited(ETH, msg.sender, msg.value);
    }

    /// @notice Deposit ERC-20 tokens (plain transfers to the vault also work; this just logs them).
    function deposit(address token, uint256 amount) external {
        if (token == ETH) revert UseReceiveForEth();
        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
        emit Deposited(token, msg.sender, amount);
    }

    // ------------------------------------------------------------------
    // Proposals
    // ------------------------------------------------------------------

    /// @notice Propose sending `amount` of `asset` to an allowlisted `to`. The proposer's approval is counted.
    function proposeWithdrawal(address asset, address to, uint256 amount) external onlyOwner returns (uint256 id) {
        if (paused) revert IsPaused();
        if (amount == 0) revert ZeroAmount();
        if (!isAllowedDestination[to]) revert DestinationNotAllowed(to);
        uint256 limit = assetPolicy[asset].dailyLimit;
        // A withdrawal larger than the bucket's capacity could never execute; fail now, not in two days.
        if (amount > limit) revert AmountExceedsDailyLimit(amount, limit);

        id = _newProposal(Kind.Withdrawal, asset, to, amount, "");
    }

    /// @notice Propose a configuration change: `data` is calldata for one of the onlySelf functions below.
    /// @dev Allowed while paused, because unpausing is itself a configuration change.
    function proposeConfig(bytes calldata data) external onlyOwner returns (uint256 id) {
        bytes4 sel = data.length >= 4 ? bytes4(data[:4]) : bytes4(0);
        if (!_isConfigSelector(sel)) revert ConfigCallNotAllowed(sel);
        id = _newProposal(Kind.Config, address(0), address(0), 0, data);
    }

    function approve(uint256 id) external onlyOwner {
        Proposal storage p = _open(id);
        if (hasApproved[id][msg.sender]) revert AlreadyApproved(id);
        hasApproved[id][msg.sender] = true;
        uint256 n = approvalCount(id);
        emit Approved(id, msg.sender, n);
        _markThresholdIfReached(id, p, n);
    }

    /// @notice Withdraw your approval. If that drops the count below M, the timelock clock resets.
    function revoke(uint256 id) external onlyOwner {
        Proposal storage p = _open(id);
        if (!hasApproved[id][msg.sender]) revert NotApproved(id);
        hasApproved[id][msg.sender] = false;
        uint256 n = approvalCount(id);
        if (n < threshold) p.thresholdReachedAt = 0;
        emit Revoked(id, msg.sender, n);
    }

    /// @notice Any single owner can cancel any open proposal. This is the veto that makes the
    ///         timelock useful: one honest owner can stop a withdrawal pushed by M compromised keys.
    function cancel(uint256 id) external onlyOwner {
        Proposal storage p = _open(id);
        p.cancelled = true;
        emit Cancelled(id, msg.sender);
    }

    /// @notice Execute a proposal that has M approvals and whose timelock (if any) has passed.
    function execute(uint256 id) external onlyOwner nonReentrant {
        Proposal storage p = _open(id);

        uint256 n = approvalCount(id);
        if (n < threshold) revert NotEnoughApprovals(id, n, threshold);

        uint256 readyAt = executableAt(id);
        // slither-disable-next-line timestamp -- the timelock is time-based by design; seconds of drift vs a >=1h delay
        if (block.timestamp < readyAt) revert TimelockActive(id, readyAt);

        // Effects before interactions: a re-entrant call sees the proposal as executed.
        p.executed = true;
        emit Executed(id, msg.sender);

        if (p.kind == Kind.Withdrawal) {
            _executeWithdrawal(id, p);
        } else {
            (bool ok, bytes memory ret) = address(this).call(p.data);
            if (!ok) revert ConfigCallFailed(ret);
        }
    }

    // ------------------------------------------------------------------
    // Emergency pause
    // ------------------------------------------------------------------

    /// @notice Any single owner can stop all withdrawals immediately.
    function pause() external onlyOwner {
        paused = true;
        emit Paused(msg.sender);
    }

    // ------------------------------------------------------------------
    // Configuration (only via an executed Config proposal)
    // ------------------------------------------------------------------

    function unpause() external onlySelf {
        paused = false;
        emit Unpaused();
    }

    function setDestination(address destination, bool allowed) external onlySelf {
        if (destination == address(0) || destination == address(this)) revert DestinationNotAllowed(destination);
        isAllowedDestination[destination] = allowed;
        emit DestinationSet(destination, allowed);
    }

    /// @dev Lowering a limit takes effect immediately (the bucket is clamped). Raising it does not
    ///      top the bucket up: the extra capacity refills over time. A newly configured asset starts
    ///      empty, so total outflow since configuration is always <= dailyLimit * elapsed / 1 day.
    function setAssetPolicy(address asset, uint128 dailyLimit, uint128 largeThreshold) external onlySelf {
        Bucket storage b = _buckets[asset];
        uint128 current = _refilled(asset);
        assetPolicy[asset] = AssetPolicy({dailyLimit: dailyLimit, largeThreshold: largeThreshold});
        // slither-disable-next-line timestamp -- clamps the bucket when the limit is lowered; `current` depends on time
        b.available = current < dailyLimit ? current : dailyLimit;
        b.lastUpdate = uint64(block.timestamp);
        emit AssetPolicySet(asset, dailyLimit, largeThreshold);
    }

    function addOwner(address owner) external onlySelf {
        if (owner == address(0) || owner == address(this) || isOwner[owner] || _owners.length >= MAX_OWNERS) {
            revert InvalidOwners();
        }
        isOwner[owner] = true;
        _owners.push(owner);
        _bumpOwnerSet();
        emit OwnerAdded(owner);
    }

    function removeOwner(address owner) external onlySelf {
        if (!isOwner[owner] || _owners.length - 1 < threshold) revert InvalidOwners();
        isOwner[owner] = false;
        for (uint256 i = 0; i < _owners.length; i++) {
            if (_owners[i] == owner) {
                _owners[i] = _owners[_owners.length - 1];
                _owners.pop();
                break;
            }
        }
        _bumpOwnerSet();
        emit OwnerRemoved(owner);
    }

    function setThreshold(uint256 newThreshold) external onlySelf {
        if (newThreshold == 0 || newThreshold > _owners.length) revert InvalidThreshold();
        threshold = newThreshold;
        _bumpOwnerSet();
        emit ThresholdChanged(newThreshold);
    }

    // ------------------------------------------------------------------
    // Views
    // ------------------------------------------------------------------

    function owners() external view returns (address[] memory) {
        return _owners;
    }

    function proposalCount() external view returns (uint256) {
        return _proposals.length;
    }

    function getProposal(uint256 id) external view returns (Proposal memory) {
        if (id >= _proposals.length) revert UnknownProposal(id);
        return _proposals[id];
    }

    /// @notice Approvals from *current* owners only: a removed owner's past approval no longer counts.
    function approvalCount(uint256 id) public view returns (uint256 n) {
        uint256 len = _owners.length;
        for (uint256 i = 0; i < len; i++) {
            if (hasApproved[id][_owners[i]]) n++;
        }
    }

    /// @notice Earliest timestamp the proposal can execute, or type(uint256).max if M approvals are missing.
    function executableAt(uint256 id) public view returns (uint256) {
        if (id >= _proposals.length) revert UnknownProposal(id);
        Proposal storage p = _proposals[id];
        if (p.thresholdReachedAt == 0) return type(uint256).max;
        return _needsTimelock(p) ? p.thresholdReachedAt + timelockDelay : p.thresholdReachedAt;
    }

    /// @notice How much of `asset` could be withdrawn right now under the rate limit.
    function availableToWithdraw(address asset) external view returns (uint256) {
        return _refilled(asset);
    }

    // ------------------------------------------------------------------
    // Internals
    // ------------------------------------------------------------------

    function _newProposal(Kind kind, address asset, address to, uint256 amount, bytes memory data)
        internal
        returns (uint256 id)
    {
        id = _proposals.length;
        _proposals.push(
            Proposal({
                kind: kind,
                asset: asset,
                to: to,
                amount: amount,
                data: data,
                createdAt: uint64(block.timestamp),
                thresholdReachedAt: 0,
                ownerSetVersion: ownerSetVersion,
                largeAtCreation: kind == Kind.Withdrawal && amount >= assetPolicy[asset].largeThreshold,
                executed: false,
                cancelled: false
            })
        );
        emit Proposed(id, kind, msg.sender);

        hasApproved[id][msg.sender] = true;
        uint256 n = approvalCount(id);
        emit Approved(id, msg.sender, n);
        _markThresholdIfReached(id, _proposals[id], n);
    }

    /// Loads a proposal that can still be acted on: exists, not executed or cancelled,
    /// not expired, and created under the current owner set and threshold.
    function _open(uint256 id) internal view returns (Proposal storage p) {
        if (id >= _proposals.length) revert UnknownProposal(id);
        p = _proposals[id];
        if (p.executed || p.cancelled) revert ProposalClosed(id);
        if (p.ownerSetVersion != ownerSetVersion) revert ProposalStale(id);
        uint256 deadline =
            p.thresholdReachedAt == 0 ? uint256(p.createdAt) + APPROVAL_WINDOW : executableAt(id) + EXECUTION_WINDOW;
        // slither-disable-next-line timestamp -- 14-day / 7-day windows; seconds of drift are irrelevant
        if (block.timestamp > deadline) revert ProposalExpired(id);
    }

    function _markThresholdIfReached(uint256 id, Proposal storage p, uint256 n) internal {
        if (n >= threshold && p.thresholdReachedAt == 0) {
            p.thresholdReachedAt = uint64(block.timestamp);
            emit ThresholdReached(id, executableAt(id));
        }
    }

    /// Large if it was large when proposed OR is large under the current policy, so changing
    /// the policy can make a pending withdrawal stricter but never looser.
    function _needsTimelock(Proposal storage p) internal view returns (bool) {
        if (p.kind == Kind.Config) return true;
        return p.largeAtCreation || p.amount >= assetPolicy[p.asset].largeThreshold;
    }

    function _executeWithdrawal(uint256 id, Proposal storage p) internal {
        if (paused) revert IsPaused();
        // Re-checked at execution: the allowlist may have changed since the proposal was made.
        if (!isAllowedDestination[p.to]) revert DestinationNotAllowed(p.to);

        uint128 available = _refilled(p.asset);
        // slither-disable-next-line timestamp -- the rate limit refills over time by design; drift moves it by a negligible amount
        if (p.amount > available) revert RateLimited(p.amount, available);
        Bucket storage b = _buckets[p.asset];
        b.available = available - uint128(p.amount);
        b.lastUpdate = uint64(block.timestamp);

        if (p.asset == ETH) {
            if (address(this).balance < p.amount) revert InsufficientVaultBalance(p.amount, address(this).balance);
            (bool ok,) = p.to.call{value: p.amount}("");
            if (!ok) revert EthTransferFailed();
        } else {
            uint256 bal = IERC20(p.asset).balanceOf(address(this));
            if (bal < p.amount) revert InsufficientVaultBalance(p.amount, bal);
            IERC20(p.asset).safeTransfer(p.to, p.amount);
        }
        emit Withdrawn(id, p.asset, p.to, p.amount);
    }

    /// Token bucket: refill at dailyLimit per day, capped at dailyLimit. Floor division
    /// means rounding always favours the vault (never lets out more than the limit).
    function _refilled(address asset) internal view returns (uint128) {
        Bucket storage b = _buckets[asset];
        uint256 limit = assetPolicy[asset].dailyLimit;
        if (limit == 0) return 0;
        uint256 refill = (limit * (block.timestamp - b.lastUpdate)) / 1 days;
        uint256 total = uint256(b.available) + refill;
        // slither-disable-next-line timestamp -- capping the bucket at the daily limit; flagged only because refill uses time
        return uint128(total < limit ? total : limit);
    }

    function _bumpOwnerSet() internal {
        ownerSetVersion++;
    }

    function _isConfigSelector(bytes4 sel) internal pure returns (bool) {
        return sel == this.unpause.selector || sel == this.setDestination.selector
            || sel == this.setAssetPolicy.selector || sel == this.addOwner.selector || sel == this.removeOwner.selector
            || sel == this.setThreshold.selector;
    }
}
