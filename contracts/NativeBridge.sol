// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@layerzerolabs/solidity-examples/contracts/token/oft/v2/OFTV2.sol";
import "@layerzerolabs/solidity-examples/contracts/token/oft/v2/interfaces/ICommonOFT.sol";
import "@chainlink/contracts-ccip/contracts/interfaces/IRouterClient.sol";
import "@chainlink/contracts-ccip/contracts/libraries/Client.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {CCIPReceiver} from "@chainlink/contracts-ccip/contracts/applications/CCIPReceiver.sol";
import {LinkTokenInterface} from "@chainlink/contracts/src/v0.8/shared/interfaces/LinkTokenInterface.sol";

contract NativeBridge is CCIPReceiver, Ownable, Pausable, ReentrancyGuard {
    enum PayFeesIn {
        Native,
        LINK
    }

    using SafeERC20 for IERC20;
    using ECDSA for bytes32;
    bytes32 public constant MESSAGE_TYPEHASH =
        keccak256(
            "Message(bytes user,uint256 amount,uint8 tokenType,address tokenAddr,uint256 nonce)"
        );
    bytes32 public constant LOCK_ERC20_TYPEHASH =
        keccak256(
            "LockERC20(address token,address sender,uint256 amount,uint256 nonce,uint256 toChainId,bytes toAddress)"
        );
    bytes32 public domainSeparator;
    address public immutable i_link;

    address[] public validators;
    uint256 public threshold;
    mapping(address => bytes32) public tokenAddressToId;
    mapping(bytes32 => address) public tokenMapping;
    mapping(bytes32 => mapping(address => bool)) public signatures;
    mapping(bytes32 => uint256) public signatureCount;
    mapping(bytes32 => MessageData) public messageData;
    mapping(bytes32 => bool) public processedMessages;
    mapping(address => uint256) public lockedTokenVL;
    mapping(address => uint256) public nonces;
    event LockedTokenVL(
        address indexed sender,
        uint256 amount,
        address destAddress,
        address destWalletAddress,
        string tokenSymbol
    );
    event MessageReceived(
        address indexed user,
        bytes32 indexed tokenId,
        address tokenAddr,
        uint256 amount,
        bytes32 messageId
    );
    event RescueTokenCCIP(address token, uint256 amount);
    event RescueTokenVL(uint256 amount);
    event UnlockedTokenVL(bytes indexed user, uint256 amount);
    event UnlockedTokenCCIP(
        bytes indexed user,
        address tokenAddr,
        uint256 amount
    );

    event SignatureSubmitted(
        bytes32 indexed messageHash,
        address indexed signer
    );
    event Executed(bytes32 indexed messageHash);
    event ValidatorAdded(address indexed validator);
    event ValidatorRemoved(address indexed validator);
    event ThresholdUpdated(uint256 newThreshold);
    event DebugAllowance(uint256 allowance);
    event DebugBalance(uint256 balance);
    event DebugTokenMapping(bytes32 tokenId, address tokenAddr);
    event DebugMsg(string message);
    event DebugFee(uint256 fee);
    event MessageSent(bytes32 indexed messageId);
    event TokenCCIPLocked(
        address indexed sender,
        address indexed token,
        uint256 amount
    );
    event DebugUnlockTokenVL(
        address user,
        uint256 amount,
        uint256 balanceBefore,
        uint256 balanceAfter
    );
    event UnlockTokenCCIP(
        address user,
        address token,
        uint256 amount,
        uint256 balanceBefore,
        uint256 balanceAfter
    );
    error AmountZero();
    error InsufficientFeeSent(uint256 sent, uint256 required);
    error InvalidDestChainSelector();
    error DestAddressZero();
    error DesWalletAddressZero();
    error AmountToBridgeZero();
    event LockedTokenCCIP(
        address indexed sender,
        address indexed token,
        uint256 amount,
        uint64 destChainSelector,
        address indexed destAddress,
        address desWalletAddress
    );

    struct MessageData {
        bytes user;
        uint256 amount;
        uint8 tokenType;
        address tokenAddr;
        uint256 nonce;
    }

    constructor(
        address _ccipRouter,
        address[] memory _validators,
        uint256 _threshold,
        address link
    ) CCIPReceiver(_ccipRouter) Ownable() {
        require(_validators.length > 0, "Validator list cannot be empty");
        require(
            _threshold > 0 && _threshold <= _validators.length,
            "Invalid threshold"
        );

        validators = _validators;
        threshold = _threshold;

        i_link = link;

        domainSeparator = keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                ),
                keccak256(bytes("NativeBridge")),
                keccak256(bytes("1")),
                block.chainid,
                address(this)
            )
        );
    }

    function setThreshold(uint256 newThreshold) external onlyOwner {
        require(newThreshold > 0, "Threshold must be > 0");
        require(
            newThreshold <= validators.length,
            "Threshold exceeds validator count"
        );
        require(
            newThreshold >= (validators.length * 2 + 2) / 3,
            "Threshold too low"
        );

        threshold = newThreshold;
        emit ThresholdUpdated(newThreshold);
    }
    function _updateThreshold() internal {
        if (validators.length == 0) {
            threshold = 0;
        } else {
            threshold = (validators.length * 2 + 2) / 3;
        }
        emit ThresholdUpdated(threshold);
    }

    // Khi thêm validator thì update luôn threshold
    function addValidator(address validator) external onlyOwner {
        require(validator != address(0), "Invalid validator address");
        require(!_isValidator(validator), "Validator already exists");
        require(validators.length < type(uint256).max, "Validator list full");

        validators.push(validator);

        _updateThreshold();

        emit ValidatorAdded(validator);
    }

    function removeValidator(address validator) external onlyOwner {
        require(_isValidator(validator), "Validator not found");

        for (uint256 i = 0; i < validators.length; i++) {
            if (validators[i] == validator) {
                validators[i] = validators[validators.length - 1];
                validators.pop();

                _updateThreshold();
                emit ValidatorRemoved(validator);
                break;
            }
        }
    }

    function getValidatorCount() external view returns (uint256) {
        return validators.length;
    }

    function hashMessage(
        MessageData memory data
    ) internal view returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(
                    "\x19\x01",
                    domainSeparator,
                    keccak256(
                        abi.encode(
                            MESSAGE_TYPEHASH,
                            keccak256(data.user),
                            data.amount,
                            data.tokenType,
                            data.tokenAddr,
                            data.nonce
                        )
                    )
                )
            );
    }

    function bytesToAddress(
        bytes memory b
    ) internal pure returns (address addr) {
        require(b.length >= 20, "Invalid user bytes");
        assembly {
            // Lấy 32 bytes từ b + 32 (bỏ qua phần length)
            // rồi shift phải 12 bytes (96 bits) để lấy đúng 20 bytes địa chỉ
            addr := div(mload(add(b, 32)), 0x1000000000000000000000000)
        }
    }

    function submitSignature(
        bytes32 messageHash,
        bytes memory signature,
        bytes memory user,
        uint256 amount,
        uint8 tokenType,
        address tokenAddr,
        uint256 nonce
    ) public {
        require(_isValidator(msg.sender), "Not validator");
        require(!signatures[messageHash][msg.sender], "Already signed");

        // Kiểm tra nonce không bị reuse theo user
        address userAddr = bytesToAddress(user);
        require(nonce == nonces[userAddr] + 1, "Invalid nonce");

        // Tạo message hash từ dữ liệu nhập, kiểm tra trùng với messageHash
        MessageData memory data = MessageData(
            user,
            amount,
            tokenType,
            tokenAddr,
            nonce
        );
        bytes32 calcHash = hashMessage(data);
        require(calcHash == messageHash, "Invalid message hash");

        // Xác thực chữ ký theo chuẩn eth-signed-message
        require(
            _verifySignature(messageHash, signature, msg.sender),
            "Invalid signature"
        );

        if (signatureCount[messageHash] == 0) {
            // Chữ ký đầu tiên, lưu dữ liệu message
            require(user.length >= 20, "Invalid user address length");
            require(amount > 0, "Amount must be > 0");

            if (tokenType == 1) {
                require(tokenAddr != address(0), "Invalid token address");
            } else if (tokenType != 0) {
                revert("Unsupported token type");
            }

            messageData[messageHash] = data;
        } else {
            // Đã có chữ ký trước đó → kiểm tra dữ liệu khớp
            MessageData memory stored = messageData[messageHash];
            require(
                stored.amount == amount &&
                    stored.tokenType == tokenType &&
                    stored.tokenAddr == tokenAddr &&
                    stored.nonce == nonce &&
                    keccak256(stored.user) == keccak256(user),
                "Data mismatch"
            );
        }

        // Đánh dấu validator đã ký, tăng số chữ ký
        signatures[messageHash][msg.sender] = true;
        signatureCount[messageHash] += 1;

        emit SignatureSubmitted(messageHash, msg.sender);

        // Nếu đủ threshold → thực thi hành động
        if (signatureCount[messageHash] >= threshold) {
            // Cập nhật nonce cho user
            nonces[userAddr] = nonce;
            _execute(messageHash);
        }
    }

    function _execute(bytes32 messageHash) internal {
        require(!processedMessages[messageHash], "Message already processed");
        MessageData memory data = messageData[messageHash];
        require(data.amount > 0, "Invalid amount");
        require(data.user.length >= 20, "Invalid user address length");
        address userAddress = address(uint160(bytes20(data.user)));
        require(userAddress != address(0), "Invalid user address");

        processedMessages[messageHash] = true;

        if (data.tokenType == 0) {
            require(
                address(this).balance >= data.amount,
                "Insufficient native token balance"
            );
            (bool sent, ) = payable(userAddress).call{value: data.amount}("");
            require(sent, "Failed to send native token");
            emit UnlockedTokenVL(data.user, data.amount);
        } else if (data.tokenType == 1) {
            require(data.tokenAddr != address(0), "Invalid token address");
            require(
                IERC20(data.tokenAddr).balanceOf(address(this)) >= data.amount,
                "Insufficient ERC20 balance"
            );
            IERC20(data.tokenAddr).safeTransfer(userAddress, data.amount);
            emit UnlockedTokenCCIP(data.user, data.tokenAddr, data.amount);
        } else {
            revert("Unsupported token type");
        }

        // Dọn dẹp dữ liệu để tránh tái xử lý
        delete messageData[messageHash];
        delete signatureCount[messageHash];
        for (uint256 i = 0; i < validators.length; i++) {
            delete signatures[messageHash][validators[i]];
        }

        emit Executed(messageHash);
    }

    function _verifySignature(
        bytes32 messageHash,
        bytes memory signature,
        address signer
    ) internal pure returns (bool) {
        // bytes32 ethSignedMessageHash = ECDSA.toEthSignedMessageHash(messageHash);
        return ECDSA.recover(messageHash, signature) == signer;
    }

    function _splitSignature(
        bytes memory sig
    ) internal pure returns (bytes32 r, bytes32 s, uint8 v) {
        require(sig.length == 65, "Invalid signature length");
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
    }

    function _isValidator(address addr) internal view returns (bool) {
        for (uint256 i = 0; i < validators.length; i++) {
            if (validators[i] == addr) return true;
        }
        return false;
    }

    function setTokenAddressToId(
        address tokenAddress,
        bytes32 tokenId
    ) external onlyOwner {
        tokenAddressToId[tokenAddress] = tokenId;
    }

    function setTokenMapping(
        bytes32 tokenId,
        address tokenAddress
    ) external onlyOwner {
        tokenMapping[tokenId] = tokenAddress;
        tokenAddressToId[tokenAddress] = tokenId;
    }

    function lockOFT(
        OFTV2 oftToken,
        uint256 amountToBridge,
        uint64 destChainId,
        address destAddress,
        address desWalletAddress
    ) external payable whenNotPaused nonReentrant {
        // require(amountToBridge > 0, "Amount must be > 0");
        // require(destAddress.length > 0, "Destination address cannot be empty");
        require(address(oftToken) != address(0), "Invalid OFT token");

        uint16 lzDestChainId = uint16(destChainId);
        require(lzDestChainId == destChainId, "destChainId overflow");

        ICommonOFT.LzCallParams memory lzParams = ICommonOFT.LzCallParams({
            refundAddress: payable(msg.sender),
            zroPaymentAddress: address(0),
            adapterParams: abi.encodePacked(uint16(1), uint256(200000))
        });

        oftToken.sendFrom{value: msg.value}(
            msg.sender,
            lzDestChainId,
            bytes32(0),
            amountToBridge,
            lzParams
        );

        emit LockedTokenCCIP(
            msg.sender,
            address(oftToken),
            amountToBridge,
            destChainId,
            destAddress,
            desWalletAddress
        );

        uint256 feeUsed = msg.value;
        if (msg.value > feeUsed) {
            payable(msg.sender).transfer(msg.value - feeUsed);
        }
    }

    function lockTokenVL(
        address destAddress,
        address destWalletAddress
    ) external payable whenNotPaused nonReentrant {

        if (msg.value == 0) {
            revert AmountZero();
        }

        lockedTokenVL[msg.sender] += msg.value;
        emit LockedTokenVL(msg.sender, msg.value, destAddress,destWalletAddress, "ETH");
    }

    function lockTokenCCIP(
        IERC20 token,
        uint64 destChainSelector,
        address destAddress,
        address desWalletAddress,
        uint256 amountToBridge,
        PayFeesIn payFeesIn
    ) external payable whenNotPaused nonReentrant returns (bytes32 messageId) {
        if (destChainSelector == 0) {
            revert InvalidDestChainSelector();
        }
        if (destAddress == address(0)) {
            revert DestAddressZero();
        }
        if (desWalletAddress == address(0)) {
            revert DesWalletAddressZero();
        }
        if (amountToBridge == 0) {
            revert AmountToBridgeZero();
        }
        require(amountToBridge > 0, "Amount must be > 0");

        // Look up tokenId
        bytes32 tokenId = tokenAddressToId[address(token)];
        require(tokenId != bytes32(0), "Unsupported token");
        emit DebugMsg("TokenId mapped");

        token.transferFrom(msg.sender, address(this), amountToBridge);

        emit TokenCCIPLocked(msg.sender, address(token), amountToBridge);
        emit DebugMsg("Token locked");

        // Build message
        Client.EVM2AnyMessage memory evmMessage = Client.EVM2AnyMessage({
            receiver: abi.encode(destAddress),
            data: abi.encode(desWalletAddress, tokenId, amountToBridge),
            tokenAmounts: new Client.EVMTokenAmount[](0),
            extraArgs: Client._argsToBytes(
                Client.GenericExtraArgsV2({
                    gasLimit: 300_000,
                    allowOutOfOrderExecution: true
                })
            ),
            feeToken: payFeesIn == PayFeesIn.LINK ? i_link : address(0)
        });

        uint256 fee = IRouterClient(getRouter()).getFee(
            destChainSelector,
            evmMessage
        );
        emit DebugFee(fee);

        if (msg.value < fee) {
            revert InsufficientFeeSent(msg.value, fee);
        }

        // Send message
        if (payFeesIn == PayFeesIn.LINK) {
            LinkTokenInterface(i_link).approve(getRouter(), fee);
            messageId = IRouterClient(getRouter()).ccipSend(
                destChainSelector,
                evmMessage
            );
        } else {
            messageId = IRouterClient(getRouter()).ccipSend{value: fee}(
                destChainSelector,
                evmMessage
            );
        }
        emit MessageSent(messageId);

        emit LockedTokenCCIP(
            msg.sender,
            address(token),
            amountToBridge,
            destChainSelector,
            destAddress,
            desWalletAddress
        );

        // Refund fee if needed
        if (msg.value > fee) {
            uint256 refund = msg.value - fee;
            (bool sent, ) = payable(msg.sender).call{value: refund}("");
            require(sent, "Refund failed");
            emit DebugMsg("Refund succeeded");
        }
    }

    function getFeeCCIP(
        uint64 destChainSelector,
        address receiver,
        bytes memory data,
        PayFeesIn payFeesIn,
        address tokenAddress,
        uint256 tokenAmount
    ) external view returns (uint256) {
        Client.EVMTokenAmount[]
            memory tokenAmounts = new Client.EVMTokenAmount[](1);
        tokenAmounts[0] = Client.EVMTokenAmount({
            token: tokenAddress,
            amount: tokenAmount
        });

        Client.EVM2AnyMessage memory message = Client.EVM2AnyMessage({
            receiver: abi.encode(receiver),
            data: data,
            tokenAmounts: tokenAmounts,
            feeToken: payFeesIn == PayFeesIn.LINK ? i_link : address(0),
            extraArgs: Client._argsToBytes(
                Client.EVMExtraArgsV1({gasLimit: 300_000})
            )
        });

        return IRouterClient(getRouter()).getFee(destChainSelector, message);
    }

    function _ccipReceive(
        Client.Any2EVMMessage memory message
    ) internal virtual override whenNotPaused nonReentrant {
        bytes32 messageId = message.messageId;

        require(!processedMessages[messageId], "Message already processed");
        processedMessages[messageId] = true;

        (address userAddress, bytes32 tokenId, uint256 amount) = abi.decode(
            message.data,
            (address, bytes32, uint256)
        );

        require(amount > 0, "Amount must be > 0");

        address tokenAddr = tokenMapping[tokenId];

        emit DebugTokenMapping(tokenId, tokenAddr);

        require(tokenAddr != address(0), "Unsupported token");

        uint256 balanceBefore = IERC20(tokenAddr).balanceOf(address(this));
        require(balanceBefore >= amount, "Insufficient ERC20 balance");

        IERC20(tokenAddr).safeTransfer(userAddress, amount);

        emit MessageReceived(
            userAddress,
            tokenId,
            tokenAddr,
            amount,
            messageId
        );
        emit UnlockTokenCCIP(
            userAddress,
            tokenAddr,
            amount,
            IERC20(tokenAddr).balanceOf(address(this)),
            IERC20(tokenAddr).balanceOf(userAddress)
        );
    }

    function rescueTokenCCIP(IERC20 token, uint256 amount) external onlyOwner {
        require(address(token) != address(0), "Invalid token address");
        require(
            token.balanceOf(address(this)) >= amount,
            "Insufficient token balance"
        );
        token.safeTransfer(owner(), amount);
        emit RescueTokenCCIP(address(token), amount);
    }

    function rescueTokenVL(uint256 amount) external onlyOwner {
        require(address(this).balance >= amount, "Insufficient native balance");
        payable(owner()).transfer(amount);
        emit RescueTokenVL(amount);
    }

    function withdraw(address payable to, uint256 amount) external onlyOwner {
        require(address(this).balance >= amount, "Insufficient balance");
        to.transfer(amount);
    }

    function pause() external onlyOwner {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }

    receive() external payable {}

    fallback() external payable {}
}
