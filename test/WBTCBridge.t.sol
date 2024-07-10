// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Test} from "forge-std/Test.sol";
import {WBTCBridge} from "../src/WBTCBridge.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

// Mock contract for WBTC token
contract WBTCMock is ERC20 {
    constructor() ERC20("Wrapped Bitcoin", "WBTC") {}

    // Mint WBTC tokens to an address
    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

// Test contract for WBTCBridge functionality
contract WBTCBridgeTest is Test {
    WBTCBridge bridge;
    WBTCMock wbtc;
    address owner;
    address user;
    address server;

    // Set up initial conditions and roles
    function setUp() public {
        owner = address(this);
        user = address(0x1);
        server = address(0x2);

        wbtc = new WBTCMock();
        bridge = new WBTCBridge(address(wbtc));

        // Grant roles to the contract
        bridge.grantRole(bridge.OWNER_ROLE(), owner);
        bridge.grantRole(bridge.SERVER_ROLE(), server);

        // Mint WBTC tokens to user and approve the bridge contract
        wbtc.mint(user, 1000 * 10 ** 18);
        vm.prank(user);
        wbtc.approve(address(bridge), 1000 * 10 ** 18);
    }

    // Test case for verifying initialization values
    function test_Initialization() public view {
        assertEq(
            address(bridge.WBTC()),
            address(wbtc),
            "WBTC address mismatch"
        );
        assertTrue(
            bridge.hasRole(bridge.OWNER_ROLE(), owner),
            "Owner role not assigned"
        );
        assertTrue(
            bridge.hasRole(bridge.SERVER_ROLE(), server),
            "Server role not assigned"
        );
    }

    // Test case for reverting deposit when the contract is stopped
    function test_RevertDepositWhen_ContractStopped() public {
        bridge.stop();
        vm.prank(user);
        vm.expectRevert(WBTCBridge.ContractStopped.selector);
        bridge.deposit(100 * 10 ** 18);
    }

    // Test case for reverting deposit when amount is zero
    function test_RevertDepositWhen_AmountIsZero() public {
        vm.prank(user);
        vm.expectRevert(WBTCBridge.AmountMustBeGreaterThanZero.selector);
        bridge.deposit(0);
    }

    // Test case for depositing WBTC tokens into the contract
    function testDeposit() public {
        uint256 amount = 200 * 10 ** 18;

        // Check state variables before deposit
        assertEq(
            bridge.balanceOf(user),
            0,
            "User WBTC balance mismatch after deposit"
        );
        assertEq(
            wbtc.balanceOf(address(bridge)),
            0,
            "Contract WBTC balance mismatch after deposit"
        );

        // Perform deposit operation
        vm.prank(user);
        vm.expectEmit(true, false, false, true);
        emit WBTCBridge.Deposited(user, amount);
        bridge.deposit(amount);

        // Check state variables after deposit
        assertEq(
            bridge.balanceOf(user),
            amount,
            "User WBTC balance mismatch after deposit"
        );
        assertEq(
            wbtc.balanceOf(address(bridge)),
            amount,
            "Contract WBTC balance mismatch after deposit"
        );
        assertEq(
            wbtc.balanceOf(user),
            800 * 10 ** 18,
            "User WBTC balance mismatch after deposit"
        );
    }

    // Test case for reverting bridge operation when the contract is stopped
    function test_RevertBridgeWhen_ContractStopped() public {
        bridge.stop();
        vm.prank(user);
        vm.expectRevert(WBTCBridge.ContractStopped.selector);
        bridge.bridge(100 * 10 ** 18);
    }

    // Test case for reverting bridge operation when amount is zero
    function test_RevertBridgeWhen_AmountIsZero() public {
        vm.prank(user);
        vm.expectRevert(WBTCBridge.AmountMustBeGreaterThanZero.selector);
        bridge.bridge(0);
    }

    // Test case for bridging WBTC tokens to another network
    function testBridge() public {
        uint256 amount = 100 * 10 ** 18;
        uint256 bridgeCount = 0;
        uint256 newTimestamp = 100;

        // Update timestamp for deterministic hash
        vm.warp(newTimestamp);
        bytes32 hash = keccak256(
            abi.encodePacked(user, amount, newTimestamp, bridgeCount)
        );

        // Perform bridge operation
        vm.prank(user);
        vm.expectEmit(true, true, true, true);
        emit WBTCBridge.Bridged(
            user,
            amount,
            hash,
            WBTCBridge.BridgeStatus.IN_TRANSIT
        );
        bytes32 bridgeHash = bridge.bridge(amount);

        // Check state variables after bridging
        (
            address messageUser,
            uint256 messageAmount,
            WBTCBridge.BridgeStatus messageStatus
        ) = bridge.bridgeMessages(bridgeHash);

        assertEq(messageUser, user, "Bridge message user mismatch");
        assertEq(messageAmount, amount, "Bridge message amount mismatch");
        assertEq(
            uint(messageStatus),
            uint(WBTCBridge.BridgeStatus.IN_TRANSIT),
            "Bridge message status mismatch"
        );

        assertEq(
            wbtc.balanceOf(address(bridge)),
            amount,
            "Contract WBTC balance mismatch after bridging"
        );
        assertEq(
            wbtc.balanceOf(user),
            900 * 10 ** 18,
            "User WBTC balance mismatch after bridging"
        );
    }

    // Test case for reverting mark delivered when caller is not authorized
    function test_RevertMarkDeliveredWhen_CallerIsNotAuthorized() public {
        uint256 amount = 100 * 10 ** 18;

        // Perform bridge operation to get a valid bridge hash
        vm.prank(user);
        bytes32 bridgeHash = bridge.bridge(amount);

        // Attempt to mark the bridge as delivered from an unauthorized address
        address unauthorized = address(0x3);
        vm.prank(unauthorized);
        vm.expectRevert("Caller is not authorized");
        bridge.markDelivered(bridgeHash);
    }

    // Test case for reverting mark delivered when bridge status is invalid
    function test_RevertMarkDeliveredWhen_InvalidStatus() public {
        bytes32 invalidHash = keccak256("invalid");
        vm.prank(server);
        vm.expectRevert(WBTCBridge.InvalidStatus.selector);
        bridge.markDelivered(invalidHash);
    }

    // Test case for marking a bridge message as delivered
    function testMarkDelivered() public {
        uint256 amount = 100 * 10 ** 18;

        // Perform bridge operation to get a valid bridge hash
        vm.prank(user);
        bytes32 bridgeHash = bridge.bridge(amount);

        // Server marks the bridge as delivered
        vm.prank(server);
        vm.expectEmit(true, false, false, false);
        emit WBTCBridge.MarkedDelivered(bridgeHash);
        bridge.markDelivered(bridgeHash);

        // Check state variables after marking delivered
        (, , WBTCBridge.BridgeStatus messageStatus) = bridge.bridgeMessages(
            bridgeHash
        );
        assertEq(
            uint(messageStatus),
            uint(WBTCBridge.BridgeStatus.DELIVERED),
            "Bridge message status mismatch after marking delivered"
        );
    }

    // Test case for reverting withdraw when contract is stopped
    function test_RevertWithdrawWhen_ContractStopped() public {
        bridge.stop();
        vm.prank(user);
        vm.expectRevert(WBTCBridge.ContractStopped.selector);
        bridge.withdraw(100 * 10 ** 18);
    }

    // Test case for reverting withdraw when amount is zero
    function test_RevertWithdrawWhen_AmountIsZero() public {
        vm.prank(user);
        vm.expectRevert(WBTCBridge.AmountMustBeGreaterThanZero.selector);
        bridge.withdraw(0);
    }

    // Test case for withdrawing WBTC tokens from the contract
    function testWithdraw() public {
        uint256 depositAmount = 200 * 10 ** 18;
        uint256 withdrawAmount = 50 * 10 ** 18;

        // Deposit WBTC tokens into the contract
        vm.prank(user);
        bridge.deposit(depositAmount);

        // Withdraw WBTC tokens from the contract
        vm.prank(user);
        bridge.withdraw(withdrawAmount);

        // Check state variables after withdrawal
        assertEq(
            bridge.balanceOf(user),
            depositAmount - withdrawAmount,
            "User WBTC balance mismatch after withdrawal"
        );
        assertEq(
            wbtc.balanceOf(user),
            850 * 10 ** 18,
            "User WBTC balance mismatch after withdrawal"
        );
    }

    // Test case for reverting bridge in when caller is not authorized
    function test_RevertBridgeInWhen_CallerIsNotAuthorized() public {
        uint256 amount = 100 * 10 ** 18;
        bytes32 bridgeInHash = keccak256(
            abi.encodePacked(
                user,
                amount,
                block.timestamp,
                bridge.bridgeCount()
            )
        );

        // Attempt to bridge in WBTC from an unauthorized address
        address unauthorized = address(0x3);
        vm.prank(unauthorized);
        vm.expectRevert("Caller is not authorized");
        bridge.bridgeIn(user, amount, bridgeInHash);
    }

    // Test case for reverting bridge in when address is invalid
    function test_RevertBridgeInWhen_InvalidAddress() public {
        uint256 amount = 100 * 10 ** 18;
        uint256 id = 1;

        bytes32 bridgeHash = keccak256(
            abi.encodePacked(user, amount, block.timestamp, id)
        );
        vm.prank(server);
        vm.expectRevert(WBTCBridge.InvalidAddress.selector);
        bridge.bridgeIn(address(0), 100 * 10 ** 18, bridgeHash);
    }

    // Test case for reverting bridge in when amount is zero
    function test_RevertBridgeInWhen_AmountIsZero() public {
        uint256 amount = 0;

        uint256 id = 1;
        bytes32 bridgeHash = keccak256(
            abi.encodePacked(user, amount, block.timestamp, id)
        );
        vm.prank(server);
        vm.expectRevert(WBTCBridge.AmountMustBeGreaterThanZero.selector);
        bridge.bridgeIn(user, 0, bridgeHash);
    }

    // Test case for reverting bridge in when bridge status is invalid
    function test_RevertBridgeInWhen_InvalidStatus() public {
        uint256 amount = 100 * 10 ** 18;

        // Deposit WBTC tokens into the contract
        vm.prank(user);
        bridge.deposit(amount);

        uint256 id = 1;
        bytes32 bridgeHash = keccak256(
            abi.encodePacked(user, amount, block.timestamp, id)
        );
        vm.prank(server);
        bridge.bridgeIn(user, amount, bridgeHash);
        vm.expectRevert(WBTCBridge.InvalidStatus.selector);
        bridge.bridgeIn(user, amount, bridgeHash);
    }

    // Test case for bridging in WBTC tokens from another network
    function testBridgeIn() public {
        uint256 amount = 100 * 10 ** 18;

        // Deposit WBTC tokens into the contract
        vm.prank(user);
        bridge.deposit(amount);

        uint256 id = 1;
        bytes32 bridgeInHash = keccak256(
            abi.encodePacked(user, amount, block.timestamp, id)
        );

        // Server bridges in WBTC tokens
        vm.prank(server);
        vm.expectEmit(true, true, false, true);
        emit WBTCBridge.BridgedIn(user, amount, bridgeInHash);
        bridge.bridgeIn(user, amount, bridgeInHash);

        // Check state variables after bridging in
        (
            address messageUser,
            uint256 messageAmount,
            WBTCBridge.BridgeStatus messageStatus
        ) = bridge.bridgeMessages(bridgeInHash);
        assertEq(messageUser, user, "Bridge message user mismatch");
        assertEq(messageAmount, amount, "Bridge message amount mismatch");
        assertEq(
            uint(messageStatus),
            uint(WBTCBridge.BridgeStatus.DELIVERED),
            "Bridge message status mismatch after bridging in"
        );

        assertEq(
            wbtc.balanceOf(user),
            1000 * 10 ** 18,
            "User WBTC balance mismatch after bridging in"
        );
    }

    // Test case for reverting stop when caller is not the owner
    function test_RevertStopWhen_CallerIsNotOwner() public {
        address unauthorized = address(0x3);
        vm.prank(unauthorized);
        vm.expectRevert("Caller is not the owner");
        bridge.stop();
    }

    // Test case for reverting start when caller is not the owner
    function test_RevertStartWhen_CallerIsNotOwner() public {
        address unauthorized = address(0x3);
        vm.prank(unauthorized);
        vm.expectRevert("Caller is not the owner");
        bridge.start();
    }

    // Test case for stopping the contract
    function testStop() public {
        // Emit stop event
        vm.expectEmit(true, false, false, false);
        emit WBTCBridge.Stopped(block.timestamp);

        // Stop the contract
        bridge.stop();

        // Check stopped state variable
        assertTrue(bridge.stopped(), "Contract should be stopped");
    }

    // Test case for starting the contract after it has been stopped
    function testStart() public {
        // Stop and then start the contract
        bridge.stop();
        vm.expectEmit(true, false, false, false);
        emit WBTCBridge.Started(block.timestamp);
        bridge.start();

        // Check stopped state variable
        assertFalse(bridge.stopped(), "Contract should be started");
    }

    // Test case for access control functions
    function test_AccessControl() public {
        address unauthorized = address(0x3);

        // Revert when unauthorized address tries to stop the contract
        vm.expectRevert("Caller is not the owner");
        vm.prank(unauthorized);
        bridge.stop();

        // Revert when unauthorized address tries to start the contract
        vm.expectRevert("Caller is not the owner");
        vm.prank(unauthorized);
        bridge.start();
    }
}
