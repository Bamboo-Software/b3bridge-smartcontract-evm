// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@chainlink/contracts-ccip/contracts/interfaces/IRouterClient.sol";
import "@chainlink/contracts-ccip/contracts/libraries/Client.sol";
import "@chainlink/contracts-ccip/contracts/applications/CCIPReceiver.sol";

contract CCIPReceiverExample is CCIPReceiver {
    event ReceivedCCIPMessage(
        bytes32 indexed messageId,
        uint64 sourceChainSelector,
        address sender,
        address desWalletAddress,
        uint256 amountToBridge,
        address token,
        uint256 tokenAmount
    );

    constructor(address router) CCIPReceiver(router) {}

    function _ccipReceive(Client.Any2EVMMessage memory message) internal override {
        // Decode message.data
        (address desWalletAddress, uint256 amountToBridge) = abi.decode(message.data, (address, uint256));

        // Assume only 1 tokenAmount is sent (your lockERC20 does that)
        Client.EVMTokenAmount memory tokenAmountData = message.destTokenAmounts[0];

        emit ReceivedCCIPMessage(
            message.messageId,
            message.sourceChainSelector,
            abi.decode(message.sender, (address)),
            desWalletAddress,
            amountToBridge,
            tokenAmountData.token,
            tokenAmountData.amount
        );

        // Bạn có thể implement xử lý tiếp ở đây nếu muốn:
        // - Ví dụ: gửi token về desWalletAddress
    }
}
