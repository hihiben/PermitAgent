// SPDX-License-Identifier: MIT
pragma solidity 0.8.17;

import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import "forge-std/Test.sol";

contract PermitAgent is Test {
    using SafeERC20 for IERC20;
    using SignatureChecker for address;

    mapping(address => uint256) public nonces;

    struct TransferRequest {
        address to;
        IERC20 token;
        uint256 amount;
    }

    function transferERC20OnPermit(
        address owner_,
        uint256 nonce_,
        TransferRequest calldata tr_,
        bytes calldata signature_
    ) external returns (bool) {
        require(nonce_ == nonces[owner_], "Invalid nonce");
        _verify(owner_, msg.sender, nonce_, signature_);
        nonces[owner_]++;
        tr_.token.safeTransferFrom(owner_, tr_.to, tr_.amount);

        return true;
    }

    function transferERC20sOnPermit(
        address owner_,
        uint256 nonce_,
        TransferRequest[] calldata trs_,
        bytes calldata signature_
    ) external returns (bool) {
        require(nonce_ == nonces[owner_], "Invalid nonce");
        _verify(owner_, msg.sender, nonce_, signature_);
        nonces[owner_]++;
        for (uint256 i = 0; i < trs_.length; i++) {
            TransferRequest memory tr = trs_[i];
            tr.token.safeTransferFrom(owner_, tr.to, tr.amount);
        }

        return true;
    }

    function revokePermit(uint256 nonce_) external {
        address owner = msg.sender;
        require(nonce_ >= nonces[owner], "Permit used");
        nonces[owner] = nonce_ + 1;
    }

    function _verify(address owner_, address spender_, uint256 nonce_, bytes memory signature_) internal view {
        bytes32 hash = keccak256(abi.encode(spender_, nonce_));
        require(owner_.isValidSignatureNow(hash, signature_), "Invalid signature");
    }
}
