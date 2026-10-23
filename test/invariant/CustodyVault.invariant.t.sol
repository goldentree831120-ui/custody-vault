// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Test, console} from "forge-std/Test.sol";
import {CustodyVault} from "../../src/CustodyVault.sol";
import {MockERC20} from "../utils/MockERC20.sol";
import {VaultHandler} from "./VaultHandler.sol";

/// 3-of-5 vault, two allowlisted destinations, one that is not.
/// Policy is fixed for the whole run, which makes the rate-limit bound exact.
contract CustodyVaultInvariantTest is Test {
    CustodyVault internal vault;
    MockERC20 internal usd;
    VaultHandler internal handler;

    address[] internal owners;
    address internal outsider = makeAddr("outsider");
    address internal treasury = makeAddr("treasury");
    address internal exchange = makeAddr("exchange");
    address internal stranger = makeAddr("stranger"); // never allowlisted

    uint256 internal constant DELAY = 1 days;
    uint128 internal constant USD_LIMIT = 1_000_000e18;
    uint128 internal constant USD_LARGE = 250_000e18;
    uint128 internal constant ETH_LIMIT = 100 ether;
    uint128 internal constant ETH_LARGE = 25 ether;
    uint256 internal constant USD_DEPOSIT = 50_000_000e18;
    uint256 internal constant ETH_DEPOSIT = 5_000 ether;

    uint256 internal policySetAt;

    function setUp() public {
        for (uint256 i = 0; i < 5; i++) {
            owners.push(makeAddr(string.concat("owner", vm.toString(i))));
        }
        vault = new CustodyVault(owners, 3, DELAY);
        usd = new MockERC20();
        usd.mint(address(vault), USD_DEPOSIT);
        vm.deal(address(vault), ETH_DEPOSIT);

        _configure(abi.encodeCall(CustodyVault.setDestination, (treasury, true)));
        _configure(abi.encodeCall(CustodyVault.setDestination, (exchange, true)));
        // Both policies are set in the same block, so one timestamp bounds both.
        uint256 a = _proposeConfig(abi.encodeCall(CustodyVault.setAssetPolicy, (address(usd), USD_LIMIT, USD_LARGE)));
        uint256 b = _proposeConfig(abi.encodeCall(CustodyVault.setAssetPolicy, (address(0), ETH_LIMIT, ETH_LARGE)));
        skip(DELAY);
        vm.startPrank(owners[0]);
        vault.execute(a);
        vault.execute(b);
        vm.stopPrank();
        policySetAt = block.timestamp;

        address[] memory dests = new address[](3);
        dests[0] = treasury;
        dests[1] = exchange;
        dests[2] = stranger;
        handler = new VaultHandler(vault, usd, owners, outsider, dests);
        targetContract(address(handler));
    }

    // ------------------------------------------------------------------
    // Invariants
    // ------------------------------------------------------------------

    /// No proposal ever executed without M distinct current-owner approvals (by the handler's own count),
    /// and the outsider never executed anything.
    function invariant_noExecutionWithoutMApprovals() public view {
        assertEq(handler.violationsThreshold(), 0);
    }

    /// Total outflow per asset never exceeds dailyLimit * days since the policy was set.
    /// (The bucket starts empty, so there is no extra initial allowance.)
    function invariant_withdrawalsNeverExceedRateLimit() public view {
        uint256 elapsed = block.timestamp - policySetAt;
        assertLe(handler.withdrawn(address(usd)), uint256(USD_LIMIT) * elapsed / 1 days);
        assertLe(handler.withdrawn(address(0)), uint256(ETH_LIMIT) * elapsed / 1 days);
    }

    /// Over ANY time window, outflow <= one full bucket + refill during the window. This is what
    /// stops a burst after idle days; the cumulative bound above does not catch that.
    function invariant_noBurstBeyondBucket() public view {
        assertEq(handler.worstWindowExcess(address(usd), USD_LIMIT), 0);
        assertEq(handler.worstWindowExcess(address(0), ETH_LIMIT), 0);
    }

    /// Large withdrawals never executed before M approvals + timelock.
    function invariant_largeWithdrawalsRespectTimelock() public view {
        assertEq(handler.violationsTimelock(), 0);
    }

    /// Nothing executed while paused.
    function invariant_nothingExecutesWhilePaused() public view {
        assertEq(handler.violationsPaused(), 0);
    }

    /// Funds only ever reach allowlisted destinations.
    function invariant_onlyAllowlistedDestinationsReceiveFunds() public view {
        assertEq(handler.violationsDestination(), 0);
        assertEq(usd.balanceOf(stranger), 0);
        assertEq(usd.balanceOf(outsider), 0);
        assertEq(stranger.balance, 0);
        assertEq(outsider.balance, 0);
        for (uint256 i = 0; i < owners.length; i++) {
            assertEq(usd.balanceOf(owners[i]), 0);
            assertEq(owners[i].balance, 0);
        }
    }

    /// Nothing is created or lost: vault + destinations always equals what was deposited.
    function invariant_conservation() public view {
        assertEq(usd.balanceOf(address(vault)) + usd.balanceOf(treasury) + usd.balanceOf(exchange), USD_DEPOSIT);
        assertEq(address(vault).balance + treasury.balance + exchange.balance, ETH_DEPOSIT);
        assertEq(handler.withdrawn(address(usd)), USD_DEPOSIT - usd.balanceOf(address(vault)));
    }

    /// Prints how much real work the fuzzer did, so a "passing" run that never executed
    /// anything would be visible.
    function afterInvariant() public view {
        console.log("proposals:", handler.proposalsCreated(), "execute attempts:", handler.executeAttempts());
        console.log("executions:", handler.executions());
        console.log("usd withdrawn:", handler.withdrawn(address(usd)) / 1e18);
        console.log("eth withdrawn:", handler.withdrawn(address(0)) / 1e18);
    }

    // ------------------------------------------------------------------
    // Setup helpers
    // ------------------------------------------------------------------

    function _proposeConfig(bytes memory data) internal returns (uint256 id) {
        vm.prank(owners[0]);
        id = vault.proposeConfig(data);
        vm.prank(owners[1]);
        vault.approve(id);
        vm.prank(owners[2]);
        vault.approve(id);
    }

    function _configure(bytes memory data) internal {
        uint256 id = _proposeConfig(data);
        skip(DELAY);
        vm.prank(owners[0]);
        vault.execute(id);
    }
}
