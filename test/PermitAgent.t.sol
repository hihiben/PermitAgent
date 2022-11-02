// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "forge-std/Test.sol";
import "../src/PermitAgent.sol";

contract PermitAgentTest is Test {
    using SafeERC20 for IERC20;

    PermitAgent internal _permitAgent;
    address internal _user;
    uint256 internal _userKey;

    IERC20 internal constant _USDT = IERC20(0xdAC17F958D2ee523a2206206994597C13D831ec7);
    IERC20 internal constant _USDC = IERC20(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48);

    function setUp() public {
        // Setup user
        (_user, _userKey) = makeAddrAndKey("User");
        vm.deal(_user, 100 ether);

        // Setup contract
        _permitAgent = new PermitAgent();
        vm.label(address(_USDT), "USDT");
        vm.label(address(_USDC), "USDC");
        vm.label(address(_permitAgent), "AGENT");
        vm.label(address(this), "TEST");
    }

    function testTransferERC20OnPermit() external {
        // Setup user
        deal(address(_USDC), _user, 100e6);
        vm.startPrank(_user);
        _USDC.safeApprove(address(_permitAgent), type(uint256).max);
        vm.stopPrank();

        address spender = address(this);
        uint256 nonce = _permitAgent.nonces(_user);
        bytes32 hash = keccak256(abi.encode(spender, nonce));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_userKey, hash);
        bytes memory signature = abi.encodePacked(r, s, v);

        PermitAgent.TransferRequest memory tr;
        tr.to = address(this);
        tr.token = _USDC;
        tr.amount = 1e6;
        _permitAgent.transferERC20OnPermit(_user, nonce, tr, signature);

        require(_USDC.balanceOf(tr.to) == tr.amount, "Incorrect balance in TEST");
    }

    function testTransferERC20sOnPermit() external {
        // Setup user
        deal(address(_USDC), _user, 100e6);
        deal(address(_USDT), _user, 100e6);
        vm.startPrank(_user);
        _USDC.safeApprove(address(_permitAgent), type(uint256).max);
        _USDT.safeApprove(address(_permitAgent), type(uint256).max);
        vm.stopPrank();

        address spender = address(this);
        uint256 nonce = _permitAgent.nonces(_user);
        bytes32 hash = keccak256(abi.encode(spender, nonce));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_userKey, hash);
        bytes memory signature = abi.encodePacked(r, s, v);

        PermitAgent.TransferRequest[] memory trs = new PermitAgent.TransferRequest[](2);
        trs[0].to = address(this);
        trs[0].token = _USDC;
        trs[0].amount = 1e6;
        trs[1].to = address(this);
        trs[1].token = _USDT;
        trs[1].amount = 1e6;
        _permitAgent.transferERC20sOnPermit(_user, nonce, trs, signature);

        require(_USDC.balanceOf(trs[0].to) == trs[0].amount, "Incorrect balance in TEST");
        require(_USDT.balanceOf(trs[1].to) == trs[1].amount, "Incorrect balance in TEST");
    }

    function testRevokePermit() external {
        // Setup user
        uint256 nonce = _permitAgent.nonces(_user);
        uint256 nonceRevoked = nonce + 10;

        vm.startPrank(_user);
        _permitAgent.revokePermit(nonceRevoked);
        vm.stopPrank();

        require(_permitAgent.nonces(_user) == nonceRevoked + 1, "Incorrect new nonce");
    }

    function testCannotUseUsedPermit() external {
        // Setup user
        deal(address(_USDC), _user, 100e6);
        vm.startPrank(_user);
        _USDC.safeApprove(address(_permitAgent), type(uint256).max);
        vm.stopPrank();

        address spender = address(this);
        uint256 nonce = _permitAgent.nonces(_user);
        bytes32 hash = keccak256(abi.encode(spender, nonce));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_userKey, hash);
        bytes memory signature = abi.encodePacked(r, s, v);

        PermitAgent.TransferRequest memory tr;
        tr.to = address(this);
        tr.token = _USDC;
        tr.amount = 1e6;
        _permitAgent.transferERC20OnPermit(_user, nonce, tr, signature);
        vm.expectRevert(bytes("Invalid nonce"));
        _permitAgent.transferERC20OnPermit(_user, nonce, tr, signature);
    }

    function testCannotFakeNonce() external {
        // Setup user
        deal(address(_USDC), _user, 100e6);
        vm.startPrank(_user);
        _USDC.safeApprove(address(_permitAgent), type(uint256).max);
        vm.stopPrank();

        address spender = address(this);
        uint256 nonce = _permitAgent.nonces(_user);
        bytes32 hash = keccak256(abi.encode(spender, nonce));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_userKey, hash);
        bytes memory signature = abi.encodePacked(r, s, v);

        PermitAgent.TransferRequest memory tr;
        tr.to = address(this);
        tr.token = _USDC;
        tr.amount = 1e6;
        _permitAgent.transferERC20OnPermit(_user, nonce, tr, signature);
        vm.expectRevert(bytes("Invalid signature"));
        _permitAgent.transferERC20OnPermit(_user, nonce + 1, tr, signature);
    }

    function testCannotUseRevokedPermit() external {
        // Setup user
        deal(address(_USDC), _user, 100e6);
        vm.startPrank(_user);
        _USDC.safeApprove(address(_permitAgent), type(uint256).max);
        vm.stopPrank();

        address spender = address(this);
        uint256 nonce = _permitAgent.nonces(_user);
        bytes32 hash = keccak256(abi.encode(spender, nonce));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_userKey, hash);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.startPrank(_user);
        _permitAgent.revokePermit(nonce);
        vm.stopPrank();

        PermitAgent.TransferRequest memory tr;
        tr.to = address(this);
        tr.token = _USDC;
        tr.amount = 1e6;
        vm.expectRevert(bytes("Invalid nonce"));
        _permitAgent.transferERC20OnPermit(_user, nonce, tr, signature);
    }
}
