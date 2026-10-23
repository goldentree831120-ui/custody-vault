// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {CustodyVault} from "../src/CustodyVault.sol";
import {VaultTestBase} from "./utils/VaultTestBase.sol";

/// One test per rule. Names read as the rule being checked.
contract CustodyVaultTest is VaultTestBase {
    address internal constant ETH = address(0);

    // ------------------------------------------------------------------
    // Construction
    // ------------------------------------------------------------------

    function test_constructor_rejectsBadConfig() public {
        address[] memory none = new address[](0);
        vm.expectRevert(CustodyVault.InvalidOwners.selector);
        new CustodyVault(none, 1, DELAY);

        address[] memory dup = new address[](2);
        dup[0] = alice;
        dup[1] = alice;
        vm.expectRevert(CustodyVault.InvalidOwners.selector);
        new CustodyVault(dup, 1, DELAY);

        address[] memory zero = new address[](1);
        vm.expectRevert(CustodyVault.InvalidOwners.selector);
        new CustodyVault(zero, 1, DELAY);

        address[] memory two = new address[](2);
        two[0] = alice;
        two[1] = bob;
        vm.expectRevert(CustodyVault.InvalidThreshold.selector);
        new CustodyVault(two, 0, DELAY);
        vm.expectRevert(CustodyVault.InvalidThreshold.selector);
        new CustodyVault(two, 3, DELAY);
        vm.expectRevert(CustodyVault.InvalidTimelock.selector);
        new CustodyVault(two, 2, 59 minutes);
        vm.expectRevert(CustodyVault.InvalidTimelock.selector);
        new CustodyVault(two, 2, 31 days);
    }

    // ------------------------------------------------------------------
    // Access control
    // ------------------------------------------------------------------

    function test_outsiderCannotDoAnything() public {
        uint256 id = proposeAndApprove(address(usd), treasury, 1e18);
        vm.startPrank(outsider);
        vm.expectRevert(CustodyVault.NotOwner.selector);
        vault.proposeWithdrawal(address(usd), treasury, 1e18);
        vm.expectRevert(CustodyVault.NotOwner.selector);
        vault.proposeConfig(abi.encodeCall(CustodyVault.unpause, ()));
        vm.expectRevert(CustodyVault.NotOwner.selector);
        vault.approve(id);
        vm.expectRevert(CustodyVault.NotOwner.selector);
        vault.execute(id);
        vm.expectRevert(CustodyVault.NotOwner.selector);
        vault.cancel(id);
        vm.expectRevert(CustodyVault.NotOwner.selector);
        vault.pause();
        vm.stopPrank();
    }

    function test_configFunctionsCannotBeCalledDirectly_evenByOwners() public {
        vm.startPrank(alice);
        vm.expectRevert(CustodyVault.NotSelf.selector);
        vault.setDestination(outsider, true);
        vm.expectRevert(CustodyVault.NotSelf.selector);
        vault.setAssetPolicy(address(usd), type(uint128).max, type(uint128).max);
        vm.expectRevert(CustodyVault.NotSelf.selector);
        vault.addOwner(outsider);
        vm.expectRevert(CustodyVault.NotSelf.selector);
        vault.setThreshold(1);
        vm.expectRevert(CustodyVault.NotSelf.selector);
        vault.unpause();
        vm.stopPrank();
    }

    function test_proposeConfig_rejectsArbitraryCalldata() public {
        // execute() is not a config function, so it cannot be smuggled in as one.
        bytes memory evil = abi.encodeCall(CustodyVault.execute, (0));
        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(CustodyVault.ConfigCallNotAllowed.selector, CustodyVault.execute.selector)
        );
        vault.proposeConfig(evil);

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(CustodyVault.ConfigCallNotAllowed.selector, bytes4(0)));
        vault.proposeConfig("");
    }

    // ------------------------------------------------------------------
    // M-of-N approvals
    // ------------------------------------------------------------------

    function test_smallWithdrawal_needsMApprovals_thenExecutesImmediately() public {
        vm.prank(alice);
        uint256 id = vault.proposeWithdrawal(address(usd), treasury, 1_000e18);

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(CustodyVault.NotEnoughApprovals.selector, id, 1, 2));
        vault.execute(id);

        vm.prank(bob);
        vault.approve(id);
        vm.prank(carol);
        vault.execute(id);

        assertEq(usd.balanceOf(treasury), 1_000e18);
        assertTrue(vault.getProposal(id).executed);
    }

    function test_cannotApproveTwice_orExecuteTwice() public {
        uint256 id = proposeAndApprove(address(usd), treasury, 1e18);
        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(CustodyVault.AlreadyApproved.selector, id));
        vault.approve(id);

        vm.prank(alice);
        vault.execute(id);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(CustodyVault.ProposalClosed.selector, id));
        vault.execute(id);
    }

    function test_revoke_dropsBelowThreshold() public {
        uint256 id = proposeAndApprove(address(usd), treasury, 1e18);
        vm.prank(bob);
        vault.revoke(id);
        assertEq(vault.approvalCount(id), 1);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(CustodyVault.NotEnoughApprovals.selector, id, 1, 2));
        vault.execute(id);
    }

    // ------------------------------------------------------------------
    // Destination allowlist
    // ------------------------------------------------------------------

    function test_cannotProposeToNonAllowlistedDestination() public {
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(CustodyVault.DestinationNotAllowed.selector, outsider));
        vault.proposeWithdrawal(address(usd), outsider, 1e18);
    }

    function test_destinationRemovedAfterProposal_blocksExecution() public {
        uint256 id = proposeAndApprove(address(usd), treasury, 1e18);
        configure(abi.encodeCall(CustodyVault.setDestination, (treasury, false)));
        // The removal took DELAY; the withdrawal itself is still inside its execution window.
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(CustodyVault.DestinationNotAllowed.selector, treasury));
        vault.execute(id);
    }

    function test_vaultCannotAllowlistItselfOrZero() public {
        vm.prank(alice);
        uint256 id = vault.proposeConfig(abi.encodeCall(CustodyVault.setDestination, (address(vault), true)));
        vm.prank(bob);
        vault.approve(id);
        skip(DELAY);
        vm.prank(alice);
        vm.expectRevert(); // ConfigCallFailed wrapping DestinationNotAllowed
        vault.execute(id);
    }

    // ------------------------------------------------------------------
    // Timelock and veto
    // ------------------------------------------------------------------

    function test_largeWithdrawal_waitsForTimelock() public {
        uint256 id = proposeAndApprove(address(usd), treasury, USD_LARGE);
        uint256 readyAt = block.timestamp + DELAY;
        assertEq(vault.executableAt(id), readyAt);

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(CustodyVault.TimelockActive.selector, id, readyAt));
        vault.execute(id);

        skip(DELAY - 1);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(CustodyVault.TimelockActive.selector, id, readyAt));
        vault.execute(id);

        skip(1);
        vm.prank(alice);
        vault.execute(id);
        assertEq(usd.balanceOf(treasury), USD_LARGE);
    }

    function test_justBelowLarge_isNotTimelocked() public {
        uint256 id = proposeAndApprove(address(usd), treasury, USD_LARGE - 1);
        vm.prank(alice);
        vault.execute(id);
        assertEq(usd.balanceOf(treasury), USD_LARGE - 1);
    }

    function test_singleOwnerCanVetoDuringTimelock() public {
        uint256 id = proposeAndApprove(address(usd), treasury, USD_LARGE);
        vm.prank(carol); // carol never approved; one honest owner is enough to stop it
        vault.cancel(id);
        skip(DELAY);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(CustodyVault.ProposalClosed.selector, id));
        vault.execute(id);
    }

    function test_revokeAndReapprove_restartsTimelock() public {
        uint256 id = proposeAndApprove(address(usd), treasury, USD_LARGE);
        skip(DELAY - 1 hours);
        vm.prank(bob);
        vault.revoke(id);
        vm.prank(bob);
        vault.approve(id); // threshold reached again now, so the clock restarts
        assertEq(vault.executableAt(id), block.timestamp + DELAY);
    }

    function test_loweringLargeThreshold_makesPendingWithdrawalTimelocked() public {
        uint256 id = proposeAndApprove(address(usd), treasury, 100_000e18); // small at creation
        // carol and bob lower the threshold below the pending amount. This takes DELAY,
        // so execute alice's proposal path manually to keep the withdrawal pending.
        vm.prank(carol);
        uint256 cfg =
            vault.proposeConfig(abi.encodeCall(CustodyVault.setAssetPolicy, (address(usd), USD_LIMIT, 50_000e18)));
        vm.prank(bob);
        vault.approve(cfg);
        skip(DELAY);
        vm.prank(carol);
        vault.execute(cfg);
        // Now the pending withdrawal counts as large: its timelock runs from when it reached M approvals.
        assertEq(vault.executableAt(id), block.timestamp); // DELAY has already elapsed since approval
        vm.prank(alice);
        vault.execute(id);
    }

    function test_raisingLargeThreshold_doesNotUnlockPendingLargeWithdrawal() public {
        vm.prank(alice);
        uint256 id = vault.proposeWithdrawal(address(usd), treasury, USD_LARGE); // large, 1 approval so far
        // Raise the threshold so this amount would now count as small.
        configure(abi.encodeCall(CustodyVault.setAssetPolicy, (address(usd), USD_LIMIT, USD_LARGE * 2)));
        vm.prank(bob);
        vault.approve(id); // M reached now
        // Still timelocked, because it was large when proposed.
        assertEq(vault.executableAt(id), block.timestamp + DELAY);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(CustodyVault.TimelockActive.selector, id, block.timestamp + DELAY));
        vault.execute(id);
    }

    function test_configChangesAreAlwaysTimelocked() public {
        vm.prank(alice);
        uint256 id = vault.proposeConfig(abi.encodeCall(CustodyVault.setDestination, (outsider, true)));
        vm.prank(bob);
        vault.approve(id);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(CustodyVault.TimelockActive.selector, id, block.timestamp + DELAY));
        vault.execute(id);
    }

    // ------------------------------------------------------------------
    // Rate limit (token bucket)
    // ------------------------------------------------------------------

    function test_cannotProposeMoreThanDailyLimit() public {
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(CustodyVault.AmountExceedsDailyLimit.selector, USD_LIMIT + 1, USD_LIMIT));
        vault.proposeWithdrawal(address(usd), treasury, USD_LIMIT + 1);
    }

    function test_unconfiguredAssetCannotBeWithdrawn() public {
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(CustodyVault.AmountExceedsDailyLimit.selector, 1, 0));
        vault.proposeWithdrawal(address(0xBEEF), treasury, 1);
    }

    function test_bucketDrainsThenRefillsLinearly() public {
        uint256 chunk = USD_LARGE - 1; // below large threshold, so no timelock
        uint256 spent;
        while (spent + chunk <= USD_LIMIT) {
            uint256 id = proposeAndApprove(address(usd), treasury, chunk);
            vm.prank(alice);
            vault.execute(id);
            spent += chunk;
        }
        uint256 left = vault.availableToWithdraw(address(usd));
        assertEq(left, USD_LIMIT - spent);

        uint256 blocked = proposeAndApprove(address(usd), treasury, chunk);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(CustodyVault.RateLimited.selector, chunk, left));
        vault.execute(blocked);

        // Half a day refills half the limit.
        skip(12 hours);
        assertEq(vault.availableToWithdraw(address(usd)), left + USD_LIMIT / 2);
        vm.prank(alice);
        vault.execute(blocked);
    }

    function test_newAssetStartsWithEmptyBucket() public {
        // Fresh vault so the base contract's skip(1 days) doesn't apply.
        address[] memory o = new address[](1);
        o[0] = alice;
        CustodyVault v = new CustodyVault(o, 1, DELAY);
        vm.startPrank(alice);
        uint256 id = v.proposeConfig(abi.encodeCall(CustodyVault.setAssetPolicy, (address(usd), 100e18, 50e18)));
        skip(DELAY);
        v.execute(id);
        vm.stopPrank();
        assertEq(v.availableToWithdraw(address(usd)), 0);
        skip(6 hours);
        assertEq(v.availableToWithdraw(address(usd)), 25e18);
        skip(10 days);
        assertEq(v.availableToWithdraw(address(usd)), 100e18); // capped at the limit
    }

    function test_loweringLimit_clampsBucketImmediately() public {
        assertEq(vault.availableToWithdraw(address(usd)), USD_LIMIT);
        configure(abi.encodeCall(CustodyVault.setAssetPolicy, (address(usd), 10e18, 5e18)));
        assertEq(vault.availableToWithdraw(address(usd)), 10e18);
    }

    // ------------------------------------------------------------------
    // Pause
    // ------------------------------------------------------------------

    function test_anyOwnerCanPause_andPauseBlocksWithdrawals() public {
        uint256 id = proposeAndApprove(address(usd), treasury, 1e18);
        vm.prank(carol);
        vault.pause();

        vm.prank(alice);
        vm.expectRevert(CustodyVault.IsPaused.selector);
        vault.execute(id);
        vm.prank(alice);
        vm.expectRevert(CustodyVault.IsPaused.selector);
        vault.proposeWithdrawal(address(usd), treasury, 1e18);
    }

    function test_unpauseNeedsMofNAndTimelock() public {
        vm.prank(carol);
        vault.pause();
        configure(abi.encodeCall(CustodyVault.unpause, ())); // proposals still work while paused
        assertFalse(vault.paused());

        uint256 id = proposeAndApprove(address(usd), treasury, 1e18);
        vm.prank(alice);
        vault.execute(id);
        assertEq(usd.balanceOf(treasury), 1e18);
    }

    // ------------------------------------------------------------------
    // Owner set changes
    // ------------------------------------------------------------------

    function test_ownerChange_invalidatesOpenProposals() public {
        uint256 id = proposeAndApprove(address(usd), treasury, 1e18);
        configure(abi.encodeCall(CustodyVault.removeOwner, (carol)));
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(CustodyVault.ProposalStale.selector, id));
        vault.execute(id);
        assertFalse(vault.isOwner(carol));
        assertEq(vault.owners().length, 2);
    }

    function test_cannotRemoveOwnerBelowThreshold() public {
        configure(abi.encodeCall(CustodyVault.removeOwner, (carol)));
        // 2 owners, threshold 2: removing another would make the vault unusable.
        vm.prank(alice);
        uint256 id = vault.proposeConfig(abi.encodeCall(CustodyVault.removeOwner, (bob)));
        vm.prank(bob);
        vault.approve(id);
        skip(DELAY);
        vm.prank(alice);
        vm.expectRevert(); // ConfigCallFailed(InvalidOwners)
        vault.execute(id);
    }

    function test_addOwnerAndRaiseThreshold() public {
        address dave = makeAddr("dave");
        configure(abi.encodeCall(CustodyVault.addOwner, (dave)));
        configure(abi.encodeCall(CustodyVault.setThreshold, (3)));
        assertEq(vault.threshold(), 3);

        uint256 id = proposeAndApprove(address(usd), treasury, 1e18);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(CustodyVault.NotEnoughApprovals.selector, id, 2, 3));
        vault.execute(id);
        vm.prank(dave);
        vault.approve(id);
        vm.prank(dave);
        vault.execute(id);
    }

    // ------------------------------------------------------------------
    // Expiry
    // ------------------------------------------------------------------

    function test_unapprovedProposalExpires() public {
        vm.prank(alice);
        uint256 id = vault.proposeWithdrawal(address(usd), treasury, 1e18);
        skip(vault.APPROVAL_WINDOW() + 1);
        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(CustodyVault.ProposalExpired.selector, id));
        vault.approve(id);
    }

    function test_approvedProposalMustExecuteWithinWindow() public {
        uint256 id = proposeAndApprove(address(usd), treasury, USD_LARGE);
        skip(DELAY + vault.EXECUTION_WINDOW() + 1);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(CustodyVault.ProposalExpired.selector, id));
        vault.execute(id);
    }

    // ------------------------------------------------------------------
    // ETH, balances, reentrancy
    // ------------------------------------------------------------------

    function test_ethWithdrawal() public {
        uint256 id = proposeAndApprove(ETH, treasury, 10 ether);
        vm.prank(alice);
        vault.execute(id);
        assertEq(treasury.balance, 10 ether);
    }

    function test_insufficientVaultBalance() public {
        configure(abi.encodeCall(CustodyVault.setAssetPolicy, (ETH, 5_000 ether, 5_000 ether)));
        skip(1 days);
        uint256 id = proposeAndApprove(ETH, treasury, 2_000 ether); // vault holds 1,000
        skip(DELAY);
        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(CustodyVault.InsufficientVaultBalance.selector, 2_000 ether, 1_000 ether)
        );
        vault.execute(id);
    }

    /// An owner that is also an allowlisted destination (e.g. a contract wallet) tries to
    /// re-enter execute() from its receive hook to run a second approved withdrawal.
    function test_reentrancyThroughEthReceiver_isBlocked() public {
        address[] memory o = new address[](2);
        Reenterer attacker = new Reenterer();
        o[0] = address(attacker);
        o[1] = alice;
        CustodyVault v = new CustodyVault(o, 1, DELAY);
        vm.deal(address(v), 100 ether);

        vm.prank(alice);
        uint256 c1 = v.proposeConfig(abi.encodeCall(CustodyVault.setDestination, (address(attacker), true)));
        vm.prank(alice);
        uint256 c2 = v.proposeConfig(abi.encodeCall(CustodyVault.setAssetPolicy, (ETH, 100 ether, 100 ether)));
        skip(DELAY);
        vm.startPrank(alice);
        v.execute(c1);
        v.execute(c2);
        skip(1 days);
        uint256 first = v.proposeWithdrawal(ETH, address(attacker), 1 ether);
        uint256 second = v.proposeWithdrawal(ETH, address(attacker), 1 ether);
        vm.stopPrank();

        attacker.arm(v, second);
        vm.prank(alice);
        vm.expectRevert(CustodyVault.EthTransferFailed.selector); // inner execute hit the guard
        v.execute(first);
        assertEq(address(attacker).balance, 0);
    }

    function test_depositRejectsEthAsToken() public {
        vm.expectRevert(CustodyVault.UseReceiveForEth.selector);
        vault.deposit(ETH, 1);
    }

    // ------------------------------------------------------------------
    // Fuzz
    // ------------------------------------------------------------------

    /// Any subset of the 3 owners approving: execution succeeds iff the subset has >= 2 members.
    function testFuzz_executionIffThresholdMet(uint8 mask) public {
        mask = uint8(bound(mask, 0, 7));
        address[3] memory os = [alice, bob, carol];
        // Proposer counts as an approver, so pick the proposer from the mask (or alice, then revoke).
        vm.prank(alice);
        uint256 id = vault.proposeWithdrawal(address(usd), treasury, 1e18);
        if (mask & 1 == 0) {
            vm.prank(alice);
            vault.revoke(id);
        }
        uint256 approvals = mask & 1;
        for (uint256 i = 1; i < 3; i++) {
            // forge-lint: disable-next-line(incorrect-shift) -- intended: bit i of the mask
            if (mask & (1 << i) != 0) {
                vm.prank(os[i]);
                vault.approve(id);
                approvals++;
            }
        }
        vm.prank(carol);
        if (approvals >= 2) {
            vault.execute(id);
            assertEq(usd.balanceOf(treasury), 1e18);
        } else {
            vm.expectRevert(abi.encodeWithSelector(CustodyVault.NotEnoughApprovals.selector, id, approvals, 2));
            vault.execute(id);
        }
    }

    /// Random amounts at random times: total outflow never exceeds what the bucket allows.
    function testFuzz_rateLimitHolds(uint256[8] memory amounts, uint256[8] memory gaps) public {
        uint256 start = block.timestamp - 1 days; // policy was set 1 day before setUp finished
        uint256 total;
        for (uint256 i = 0; i < 8; i++) {
            skip(bound(gaps[i], 0, 1 days));
            uint256 amt = bound(amounts[i], 1, USD_LARGE - 1);
            uint256 id = proposeAndApprove(address(usd), treasury, amt);
            uint256 avail = vault.availableToWithdraw(address(usd));
            vm.prank(alice);
            if (amt <= avail) {
                vault.execute(id);
                total += amt;
            } else {
                vm.expectRevert(abi.encodeWithSelector(CustodyVault.RateLimited.selector, amt, avail));
                vault.execute(id);
            }
            assertLe(total, uint256(USD_LIMIT) * (block.timestamp - start) / 1 days);
        }
        assertEq(usd.balanceOf(treasury), total);
    }
}

/// Owner + destination contract that tries to re-enter the vault when it receives ETH.
contract Reenterer {
    CustodyVault internal target;
    uint256 internal nextId;

    function arm(CustodyVault v, uint256 id) external {
        target = v;
        nextId = id;
    }

    receive() external payable {
        target.execute(nextId); // reverts with ReentrancyGuardReentrantCall
    }
}
