// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "../contracts/NativeBridge.sol";
import "@chainlink/contracts-ccip/contracts/interfaces/IRouterClient.sol";
import "@chainlink/contracts-ccip/contracts/libraries/Client.sol";

// Mock CCIP Router to be used in unit tests
contract MockCCIPRouter is IRouterClient {
    event MessageSent(uint64 destinationChainId, bytes destinationAddress, bytes data);

    uint256 public fee = 1e15; // 0.001 ether mặc định

    function setFee(uint256 _fee) external {
        fee = _fee;
    }

    function getFee(
        uint64 /*destChainSelector*/,
        Client.EVM2AnyMessage memory /*evmMessage*/
    ) public view override returns (uint256) {
        return fee;
    }

    function sendMessage(
        uint64 destinationChainId,
        bytes calldata destinationAddress,
        bytes calldata data
    ) external payable returns (bytes32 messageId) {
        emit MessageSent(destinationChainId, destinationAddress, data);
        return keccak256(abi.encodePacked(destinationChainId, destinationAddress, data));
    }

    // Nếu NativeBridge còn gọi ccipSend thì mock luôn hàm này:
    function ccipSend(
        uint64,
        Client.EVM2AnyMessage memory
    ) public payable override returns (bytes32) {
        return keccak256("mock");
    }

    // Gọi hàm nhận message từ contract
    function callReceive(address payable bridge, bytes memory data) public {
        Client.Any2EVMMessage memory message = abi.decode(data, (Client.Any2EVMMessage));
        NativeBridge(bridge).ccipReceive(message);
    }

    function isChainSupported(
        uint64 /*chainSelector*/
    ) external pure override returns (bool) {
        return true;
    }
}
