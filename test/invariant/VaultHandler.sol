// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {CommonBase} from "forge-std/Base.sol";
import {StdCheats} from "forge-std/StdCheats.sol";
import {StdUtils} from "forge-std/StdUtils.sol";
import {CustodyVault} from "../../src/CustodyVault.sol";
import {MockERC20} from "../utils/MockERC20.sol";

/// The fuzzer calls these functions in random order with random arguments.
///
/// The handler keeps its OWN model of approvals, timelocks and pause state,
/// built only from calls that succeeded. After every successful `execute` it
/// checks the vault against that model. Using an independent model (instead
/// of reading the vault's own bookkeeping) is what makes the invariants mean
/// something: a bug in the vault's counting would not also be in the check.
contract VaultHandler is CommonBase, StdCheats, StdUtils {
    CustodyVault public immutable vault;
    MockERC20 public immutable usd;
    uint256 public immutable delay;
    uint256 public immutable threshold;

    address[] public owners;
    address public immutable outsider;
    address[] public destinations; // [0], [1] allowlisted, [2] not
    mapping(address => bool) public allowlisted;

    struct Model {
        address asset;
        address to;
        uint256 amount;
        bool large;
        uint256 thresholdAt; // when the model's approval count first reached M (0 = not reached)
        bool closed;
    }

    Model[] public props;
    uint256[] public vaultIds; // props[i] corresponds to vault proposal vaultIds[i]
    mapping(uint256 => mapping(address => bool)) public approved; // model index => owner => approved
    bool public paused;

    // Ghost totals and violation counters read by the invariant contract.
    mapping(address => uint256) public withdrawn;
    // Every executed withdrawal per asset, in order, for the sliding-window check.
    mapping(address => uint256[]) internal _wTimes;
    mapping(address => uint256[]) internal _wAmounts;
    uint256 public violationsThreshold;
    uint256 public violationsTimelock;
    uint256 public violationsPaused;
    uint256 public violationsDestination;
    uint256 public executions;
    uint256 public proposalsCreated;
    uint256 public executeAttempts;
    mapping(bytes4 => uint256) public calls;

    address internal constant ETH = address(0);

    constructor(CustodyVault v, MockERC20 u, address[] memory o, address out, address[] memory dests) {
        vault = v;
        usd = u;
        delay = v.timelockDelay();
        threshold = v.threshold();
        owners = o;
        outsider = out;
        destinations = dests;
        allowlisted[dests[0]] = true;
        allowlisted[dests[1]] = true;
    }

    // ------------------------------------------------------------------
    // Actions
    // ------------------------------------------------------------------

    function propose(uint256 ownerSeed, uint256 assetSeed, uint256 destSeed, uint256 amount) external {
        calls[this.propose.selector]++;
        _propose(ownerSeed, assetSeed, destSeed, amount);
    }

    function _propose(uint256 ownerSeed, uint256 assetSeed, uint256 destSeed, uint256 amount) internal returns (bool) {
        address owner = _owner(ownerSeed);
        address asset = assetSeed % 2 == 0 ? address(usd) : ETH;
        address to = destinations[destSeed % destinations.length];
        (uint128 limit, uint128 large) = vault.assetPolicy(asset);
        // Mix of sizes: mostly small, some large (timelocked), occasionally over the limit.
        uint256 r = amount % 10;
        if (r < 6) amount = bound(amount, 1, uint256(large) - 1);
        else if (r < 9) amount = bound(amount, large, limit);
        else amount = uint256(limit) + 1;
        return _proposeExact(owner, asset, to, amount, large);
    }

    function _proposeExact(address owner, address asset, address to, uint256 amount, uint256 large)
        internal
        returns (bool)
    {
        vm.prank(owner);
        try vault.proposeWithdrawal(asset, to, amount) returns (uint256 id) {
            proposalsCreated++;
            props.push(Model(asset, to, amount, amount >= large, 0, false));
            vaultIds.push(id);
            _setApproval(props.length - 1, owner, true);
            return true;
        } catch {
            return false;
        }
    }

    /// Idle for a few days, then try to pull many small (not timelocked) withdrawals at once.
    /// This is the pattern a capped bucket must stop: without the cap, idle days would let
    /// several days' worth out in one burst. Random sequences rarely line this up on their own
    /// (the burst invariant caught an uncapped bucket in only ~3 of 10 runs without this action).
    function idleThenBurst(uint256 seed) external {
        calls[this.idleThenBurst.selector]++;
        if (paused) return;
        skip(bound(seed, 2 days, 5 days));
        address asset = seed % 2 == 0 ? address(usd) : ETH;
        (, uint128 large) = vault.assetPolicy(asset);
        address to = destinations[seed % 2]; // an allowlisted one
        for (uint256 j = 0; j < 8; j++) {
            if (!_proposeExact(_owner(seed + j), asset, to, uint256(large) - 1, large)) return;
            uint256 i = props.length - 1;
            for (uint256 k = 1; k < threshold; k++) {
                _approve(i, owners[((seed + j) % owners.length + k) % owners.length]);
            }
            _execute(_owner(seed + j), i);
        }
    }

    /// The common honest path in one call: propose, then M-1 more owners approve.
    /// Without this the fuzzer rarely lines up 3 separate approvals on the same proposal
    /// and the run would "pass" without ever executing anything.
    function proposeAndCollect(uint256 ownerSeed, uint256 assetSeed, uint256 destSeed, uint256 amount) external {
        calls[this.proposeAndCollect.selector]++;
        if (!_propose(ownerSeed, assetSeed, destSeed, amount)) return;
        uint256 i = props.length - 1;
        for (uint256 k = 1; k < threshold; k++) {
            _approve(i, owners[(ownerSeed % owners.length + k) % owners.length]);
        }
    }

    function approve(uint256 ownerSeed, uint256 propSeed) external {
        calls[this.approve.selector]++;
        if (props.length == 0) return;
        _approve(_pick(propSeed), _owner(ownerSeed));
    }

    function _approve(uint256 i, address owner) internal {
        vm.prank(owner);
        try vault.approve(vaultIds[i]) {
            _setApproval(i, owner, true);
        } catch {}
    }

    function revoke(uint256 ownerSeed, uint256 propSeed) external {
        calls[this.revoke.selector]++;
        if (props.length == 0) return;
        uint256 i = _pick(propSeed);
        address owner = _owner(ownerSeed);
        vm.prank(owner);
        try vault.revoke(vaultIds[i]) {
            _setApproval(i, owner, false);
        } catch {}
    }

    function cancel(uint256 ownerSeed, uint256 propSeed) external {
        calls[this.cancel.selector]++;
        if (props.length == 0 || ownerSeed % 5 != 0) return; // vetoes are rare in practice
        uint256 i = _pick(propSeed);
        vm.prank(_owner(ownerSeed));
        try vault.cancel(vaultIds[i]) {
            props[i].closed = true;
        } catch {}
    }

    /// Executor is any owner OR the outsider.
    function execute(uint256 actorSeed, uint256 propSeed) external {
        calls[this.execute.selector]++;
        if (props.length == 0) return;
        address actor = actorSeed % (owners.length + 1) == owners.length ? outsider : _owner(actorSeed);
        _execute(actor, _pick(propSeed));
    }

    function _execute(address actor, uint256 i) internal {
        Model storage m = props[i];
        executeAttempts++;
        uint256 before = _balance(m.asset, m.to);
        vm.prank(actor);
        try vault.execute(vaultIds[i]) {
            executions++;
            m.closed = true;
            uint256 count = _modelCount(i);
            if (count < threshold) violationsThreshold++;
            if (actor == outsider) violationsThreshold++;
            if (m.large && block.timestamp < m.thresholdAt + delay) violationsTimelock++;
            if (paused) violationsPaused++;
            if (!allowlisted[m.to]) violationsDestination++;
            uint256 got = _balance(m.asset, m.to) - before;
            withdrawn[m.asset] += got;
            _wTimes[m.asset].push(block.timestamp);
            _wAmounts[m.asset].push(got);
        } catch {}
    }

    function pause(uint256 ownerSeed) external {
        calls[this.pause.selector]++;
        if (ownerSeed % 10 != 0) return; // pause rarely, or the run spends most of its time paused
        vm.prank(_owner(ownerSeed));
        vault.pause();
        paused = true;
    }

    /// Unpause through governance in one step: propose, collect M approvals, wait, execute.
    function unpauseViaGovernance() external {
        calls[this.unpauseViaGovernance.selector]++;
        if (!paused) return;
        vm.prank(owners[0]);
        uint256 id = vault.proposeConfig(abi.encodeCall(CustodyVault.unpause, ()));
        for (uint256 k = 1; k < threshold; k++) {
            vm.prank(owners[k]);
            vault.approve(id);
        }
        skip(delay);
        vm.prank(owners[0]);
        vault.execute(id);
        paused = false;
    }

    function warp(uint256 secs) external {
        calls[this.warp.selector]++;
        skip(bound(secs, 1, 2 days));
    }

    // ------------------------------------------------------------------
    // Model helpers
    // ------------------------------------------------------------------

    function _setApproval(uint256 i, address owner, bool on) internal {
        approved[i][owner] = on;
        uint256 count = _modelCount(i);
        if (count >= threshold && props[i].thresholdAt == 0) props[i].thresholdAt = block.timestamp;
        if (count < threshold) props[i].thresholdAt = 0;
    }

    /// Mostly act on one of the 4 newest proposals (that is where the action is), sometimes on any.
    function _pick(uint256 seed) internal view returns (uint256) {
        uint256 n = props.length;
        if (seed % 4 != 0 || n <= 4) return n - 1 - (seed / 4) % (n < 4 ? n : 4);
        return (seed / 4) % n;
    }

    function _modelCount(uint256 i) internal view returns (uint256 n) {
        for (uint256 k = 0; k < owners.length; k++) {
            if (approved[i][owners[k]]) n++;
        }
    }

    function _owner(uint256 seed) internal view returns (address) {
        return owners[seed % owners.length];
    }

    function _balance(address asset, address who) internal view returns (uint256) {
        return asset == ETH ? who.balance : usd.balanceOf(who);
    }

    /// Token-bucket guarantee: for ANY two withdrawals i <= k, everything withdrawn from i to k
    /// is at most one full bucket plus what refilled in between:
    ///     sum(amounts[i..k]) <= limit + limit * (t[k] - t[i]) / 1 day
    /// Returns the worst excess found (0 = the guarantee held for every window).
    function worstWindowExcess(address asset, uint256 limit) external view returns (uint256 worst) {
        uint256[] storage t = _wTimes[asset];
        uint256[] storage a = _wAmounts[asset];
        for (uint256 i = 0; i < t.length; i++) {
            uint256 sum;
            for (uint256 k = i; k < t.length; k++) {
                sum += a[k];
                uint256 allowed = limit + (limit * (t[k] - t[i])) / 1 days;
                if (sum > allowed && sum - allowed > worst) worst = sum - allowed;
            }
        }
    }

    function ownersLength() external view returns (uint256) {
        return owners.length;
    }
}
