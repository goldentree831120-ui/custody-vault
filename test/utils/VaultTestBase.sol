// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Test} from "forge-std/Test.sol";
import {CustodyVault} from "../../src/CustodyVault.sol";
import {MockERC20} from "./MockERC20.sol";

/// Shared setup: a 2-of-3 vault, one allowlisted treasury address, and policies for
/// ETH and a mock stablecoin, already configured through real Config proposals.
abstract contract VaultTestBase is Test {
    CustodyVault internal vault;
    MockERC20 internal usd;

    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");
    address internal carol = makeAddr("carol");
    address internal outsider = makeAddr("outsider");
    address internal treasury = makeAddr("treasury");

    uint256 internal constant DELAY = 2 days;
    uint128 internal constant USD_LIMIT = 1_000_000e18; // per 24h
    uint128 internal constant USD_LARGE = 250_000e18; // timelocked at or above this
    uint128 internal constant ETH_LIMIT = 100 ether;
    uint128 internal constant ETH_LARGE = 25 ether;

    function setUp() public virtual {
        address[] memory owners = new address[](3);
        owners[0] = alice;
        owners[1] = bob;
        owners[2] = carol;
        vault = new CustodyVault(owners, 2, DELAY);
        usd = new MockERC20();

        usd.mint(address(this), 10_000_000e18);
        usd.approve(address(vault), type(uint256).max);
        vault.deposit(address(usd), 10_000_000e18);
        vm.deal(address(this), 1_000 ether);
        (bool ok,) = address(vault).call{value: 1_000 ether}("");
        require(ok);

        configure(abi.encodeCall(CustodyVault.setDestination, (treasury, true)));
        configure(abi.encodeCall(CustodyVault.setAssetPolicy, (address(usd), USD_LIMIT, USD_LARGE)));
        configure(abi.encodeCall(CustodyVault.setAssetPolicy, (vault.ETH(), ETH_LIMIT, ETH_LARGE)));

        // Buckets start empty when an asset is configured; let them fill.
        skip(1 days);
    }

    /// Run a config change through the full flow: alice proposes, bob approves, wait, execute.
    function configure(bytes memory data) internal returns (uint256 id) {
        vm.prank(alice);
        id = vault.proposeConfig(data);
        vm.prank(bob);
        vault.approve(id);
        skip(DELAY);
        vm.prank(alice);
        vault.execute(id);
    }

    /// alice proposes, bob approves. Returns the proposal id.
    function proposeAndApprove(address asset, address to, uint256 amount) internal returns (uint256 id) {
        vm.prank(alice);
        id = vault.proposeWithdrawal(asset, to, amount);
        vm.prank(bob);
        vault.approve(id);
    }
}
