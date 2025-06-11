// SPDX-License-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@layerzerolabs/solidity-examples/contracts/token/oft/v2/OFTV2.sol";
import "@layerzerolabs/solidity-examples/contracts/token/oft/v2/interfaces/IOFTV2.sol";

contract MockOFT is OFTV2 {
    constructor(address _lzEndpoint)
        OFTV2("MockOFT", "MOFT", 6, _lzEndpoint)
    {
        // Mint initial tokens to deployer for testing
        _mint(msg.sender, 1_000_000 * 10**6); // 1M tokens with 8 decimals
    }

    // Mint function for testing
    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    // Override sendFrom to match BaseOFTV2 interface and emit SendToChain event
    function sendFrom(
        address _from,
        uint16 _dstChainId,
        bytes32 _toAddress,
        uint256 _amount,
        IOFTV2.LzCallParams calldata _callParams
    ) public payable override {
        // Check allowance and spend it
        require(allowance(_from, msg.sender) >= _amount, "Insufficient allowance");
        _spendAllowance(_from, msg.sender, _amount);
        
        // Burn tokens from sender
        _burn(_from, _amount);

        // Emit Transfer event
        emit Transfer(_from, address(0), _amount);

        // Emit SendToChain event for test verification
        emit SendToChain(_from, _dstChainId, _toAddress, _amount, abi.encode(_callParams));
    }

    // Event to match test expectations
    event SendToChain(
        address indexed sender,
        uint16 indexed dstChainId,
        bytes32 indexed toAddress,
        uint256 amount,
        bytes callParams
    );
}