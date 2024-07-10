// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// @title WBTC Bridge Contract
/// @notice This contract allows users to deposit WBTC tokens and bridge them to another network.
contract WBTCBridge is ERC20, AccessControl, ReentrancyGuard {
    // Immutable variables
    IERC20 public immutable WBTC;

    // Roles for access control
    bytes32 public constant OWNER_ROLE = keccak256("OWNER_ROLE");
    bytes32 public constant SERVER_ROLE = keccak256("SERVER_ROLE");

    // Constants
    bytes4 public constant TRANSFER_FROM_SELECTOR = 0x23b872dd;
    bytes4 public constant TRANSFER_SELECTOR = 0xa9059cbb;

    // State variables
    uint256 public bridgeCount;
    bool public stopped;

    // Enum
    enum BridgeStatus {
        NONE,
        IN_TRANSIT,
        DELIVERED
    }

    // Structs
    struct BridgeMessage {
        address user;
        uint256 amount;
        BridgeStatus status;
    }

    // Mappings
    mapping(bytes32 => BridgeMessage) public bridgeMessages;

    // Events
    event Deposited(address indexed user, uint256 amount);
    event Bridged(
        address indexed user,
        uint256 indexed amount,
        bytes32 indexed bridgeHash,
        BridgeStatus status
    );
    event MarkedDelivered(bytes32 indexed bridgeHash);
    event Withdrawn(address indexed user, uint256 amount);
    event BridgedIn(
        address indexed user,
        uint256 indexed amount,
        bytes32 bridgeHash
    );
    event Stopped(uint256 indexed startTime);
    event Started(uint256 indexed stopTime);

    // Custom Errors
    error InvalidAddress();
    error AmountMustBeGreaterThanZero();
    error TransferFailed();
    error InsufficientBalance();
    error InvalidStatus();
    error ContractStopped();

    /// @notice Constructor to initialize the contract
    /// @param _wbtc Address of the WBTC token contract
    constructor(address _wbtc) ERC20("WBTC Share", "WBTCs") {
        if (_wbtc == address(0)) revert InvalidAddress();
        WBTC = IERC20(_wbtc);

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(OWNER_ROLE, msg.sender);
        _grantRole(SERVER_ROLE, msg.sender);
    }

    /// @notice Deposit WBTC tokens into the contract
    /// @param amount Amount of WBTC tokens to deposit
    function deposit(uint256 amount) external nonReentrant {
        if (stopped) revert ContractStopped();
        if (amount == 0) revert AmountMustBeGreaterThanZero();

        // WBTC.transferFrom(msg.sender, address(this), amount);
        _transferFrom(msg.sender, address(this), amount);

        _mint(msg.sender, amount);
        emit Deposited(msg.sender, amount);
    }

    /// @notice Bridge WBTC tokens to another network
    /// @param amount Amount of WBTC tokens to bridge
    /// @return bridgeHash Unique hash representing the bridge message
    function bridge(uint256 amount) external nonReentrant returns (bytes32) {
        if (stopped) revert ContractStopped();
        if (amount == 0) revert AmountMustBeGreaterThanZero();

        // WBTC.transferFrom(msg.sender, address(this), amount);
        _transferFrom(msg.sender, address(this), amount);
        bytes32 bridgeHash = keccak256(
            abi.encodePacked(msg.sender, amount, block.timestamp, bridgeCount++)
        );
        bridgeMessages[bridgeHash] = BridgeMessage({
            user: msg.sender,
            amount: amount,
            status: BridgeStatus.IN_TRANSIT
        });

        emit Bridged(msg.sender, amount, bridgeHash, BridgeStatus.IN_TRANSIT);
        return bridgeHash;
    }

    /// @notice Mark a bridge message as delivered
    /// @param bridgeHash Unique hash representing the bridge message
    function markDelivered(bytes32 bridgeHash) external {
        require(hasRole(SERVER_ROLE, msg.sender), "Caller is not authorized");

        BridgeMessage storage message = bridgeMessages[bridgeHash];
        if (message.status != BridgeStatus.IN_TRANSIT) revert InvalidStatus();

        message.status = BridgeStatus.DELIVERED;
        emit MarkedDelivered(bridgeHash);
    }

    /// @notice Withdraw WBTC tokens by burning share tokens
    /// @param amount Amount of share tokens to burn
    function withdraw(uint256 amount) external nonReentrant {
        if (stopped) revert ContractStopped();
        if (amount == 0) revert AmountMustBeGreaterThanZero();

        _burn(msg.sender, amount);
        // WBTC.transfer(msg.sender, amount);
        _transferWbtc(msg.sender, amount);

        emit Withdrawn(msg.sender, amount);
    }

    /// @notice Transfer WBTC to a user from another network
    /// @param user Address of the user to receive the WBTC
    /// @param amount Amount of WBTC tokens to transfer
    /// @param bridgeInHash Unique hash representing the bridge message
    function bridgeIn(
        address user,
        uint256 amount,
        bytes32 bridgeInHash
    ) external nonReentrant {
        require(hasRole(SERVER_ROLE, msg.sender), "Caller is not authorized");

        if (user == address(0)) revert InvalidAddress();
        if (amount == 0) revert AmountMustBeGreaterThanZero();
        if (bridgeMessages[bridgeInHash].status != BridgeStatus.NONE)
            revert InvalidStatus();

        bridgeMessages[bridgeInHash] = BridgeMessage({
            user: user,
            amount: amount,
            status: BridgeStatus.DELIVERED
        });

        // WBTC.transfer(user, amount);
        _transferWbtc(user, amount);
        emit BridgedIn(user, amount, bridgeInHash);
    }

    /// @notice Stop the contract operations in case of an emergency
    function stop() external {
        require(hasRole(OWNER_ROLE, msg.sender), "Caller is not the owner");
        // stopped = true;
        assembly {
            sstore(stopped.slot, 1)
        }
        emit Stopped(block.number);
    }

    /// @notice Resume the contract operations
    function start() external {
        require(hasRole(OWNER_ROLE, msg.sender), "Caller is not the owner");
        // stopped = false;
        assembly {
            sstore(stopped.slot, 0)
        }
        emit Started(block.number);
    }

    function _transferFrom(
        address sender,
        address receiver,
        uint256 _amount
    ) private {
        address wbtcAddress = address(WBTC);

        assembly {
            let fmp := mload(0x40)
            mstore(fmp, TRANSFER_FROM_SELECTOR)
            mstore(add(fmp, 0x04), sender)
            mstore(add(fmp, 0x24), receiver)
            mstore(add(fmp, 0x44), _amount)

            let result := call(gas(), wbtcAddress, 0, fmp, 0x64, 0, 0)

            if eq(result, 0) {
                revert(0, 0)
            }
        }
    }

    function _transferWbtc(address receiver, uint256 _amount) private {
        address wbtcAddress = address(WBTC);

        assembly {
            let fmp := mload(0x40)
            mstore(fmp, TRANSFER_SELECTOR)
            mstore(add(fmp, 0x04), receiver)
            mstore(add(fmp, 0x24), _amount)

            let result := call(gas(), wbtcAddress, 0, fmp, 0x44, 0, 0)

            if eq(result, 0) {
                revert(0, 0)
            }
        }
    }
}
