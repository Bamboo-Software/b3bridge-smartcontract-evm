const { expect } = require("chai");
const { ethers } = require("hardhat");
const { AbiCoder } = require("ethers");

describe("NativeBridge", function () {
   console.log("Running NativeBridge tests123...");
  let owner, validator1, validator2, validator3, nonValidator, user;
  let mockERC20, mockRouter, nativeBridge, amount;
  const link = "0x779877A7B0D9E8603169DdbD7836e478b4624789";
  beforeEach(async function () {
    const signers = await ethers.getSigners();
    owner = signers[0];
    validator1 = signers[1];
    validator2 = signers[2];
    validator3 = signers[3];
    nonValidator = signers[4];
    user = signers[5];
    amount = ethers.parseEther("10");
 console.log("Owner address:", owner.address);
    // Deploy MockERC20
    const MockERC20Factory = await ethers.getContractFactory("MockERC20");
    mockERC20 = await MockERC20Factory.deploy("MockToken", "MTK", 18);
    await mockERC20.waitForDeployment();

    // Deploy NativeBridge với mockRouter
    const NativeBridge = await ethers.getContractFactory("NativeBridge");
    nativeBridge = await NativeBridge.deploy(
      link,
      [validator1.address, validator2.address, validator3.address],
      3,
      link
    );
    await nativeBridge.waitForDeployment();

    // // Fund NativeBridge contract with 10 ETH
    // const tx = await owner.sendTransaction({
    //   to: nativeBridge.target,
    //   value: ethers.parseEther("10"),
    // });
    // await tx.wait();

    // // Mint token cho user trước khi approve và lock
    // await mockERC20.mint(user.address, amount);

    // Logging deployment info
    console.log("=== Deployment Info ===");
    console.log("Owner address:", owner.address);
    console.log("Validator1 address:", validator1.address);
    console.log("Validator2 address:", validator2.address);
    console.log("Validator3 address:", validator3.address);
    console.log("NonValidator address:", nonValidator.address);
    console.log("User address:", user.address);
    console.log("MockRouter deployed at:", mockRouter.target);
    console.log("MockERC20 deployed at:", mockERC20.target);
    console.log("NativeBridge deployed at:", nativeBridge.target);
    console.log("Funded NativeBridge with 10 ETH");
    console.log("=======================");
  });
});


//   describe("Lock Native", () => {
//     const destChainSelector = 16015286601757825753n;
//     const desWalletAddress = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e";

//     it("should revert if destAddress length != 20", async () => {
//       const shortDestAddress = ethers.hexlify(ethers.randomBytes(2));
//       await expect(
//         nativeBridge.connect(user).lockTokenVL(
//           destChainSelector,
//           shortDestAddress,
//           desWalletAddress,
//           { value: ethers.parseEther("1.01") }
//         )
//       ).to.be.revertedWith("Destination address must be 20 bytes");
//     });

//     it("should emit LockedNative and call ccipSend", async () => {
//       const amount = ethers.parseEther("10");
//       const fee = ethers.parseEther("0.01");
//       const destAddress = ethers.hexlify(ethers.randomBytes(20));
//       await expect(
//         nativeBridge.connect(user).lockNative(
//           destChainSelector,
//           destAddress,
//           desWalletAddress,
//           amount,
//           { value: amount + fee }
//         )
//       )
//         .to.emit(nativeBridge, "LockedNative")
//         .withArgs(user.address, amount, destChainSelector, destAddress, desWalletAddress);
//     });
//   });



//   describe("Validator Management", function () {
//     it("Should allow owner to add a new validator", async function () {
//   const newValidator = nonValidator;

//   await expect(nativeBridge.connect(owner).addValidator(newValidator.address))
//     .to.emit(nativeBridge, "ValidatorAdded")
//     .withArgs(newValidator.address);

//   const validators = [];
//   // Vì đã biết có 3 ban đầu, và 1 mới thêm => tổng 4
//   for (let i = 0; i < 4; i++) {
//     const v = await nativeBridge.validators(i);
//     validators.push(v);
//   }

//   expect(validators).to.include(newValidator.address);
//   expect(validators.length).to.equal(4);
//   expect(await nativeBridge.threshold()).to.equal(Math.ceil((4 * 2) / 3)); // 3
// });

//     it("Should revert if non-owner tries to add validator", async function () {
//       await expect(
//         nativeBridge.connect(nonValidator).addValidator(nonValidator.address)
//       ).to.be.revertedWith("Ownable: caller is not the owner");
//     });

//     it("Should revert if adding zero address as validator", async function () {
//       await expect(
//         nativeBridge.connect(owner).addValidator("0x0000000000000000000000000000000000000000")
//       ).to.be.revertedWith("Invalid validator address");
//     });

//     it("Should revert if adding existing validator", async function () {
//       await expect(
//         nativeBridge.connect(owner).addValidator(validator1.address)
//       ).to.be.revertedWith("Validator already exists");
//     });

//   it("Should allow owner to remove a validator", async function () {
//     await expect(nativeBridge.connect(owner).removeValidator(validator3.address))
//       .to.emit(nativeBridge, "ValidatorRemoved")
//       .withArgs(validator3.address);

//     const validators = [];
//     const count = await nativeBridge.getValidatorCount();
//     for (let i = 0; i < count; i++) {
//       validators.push(await nativeBridge.validators(i));
//     }

//     expect(validators).to.not.include(validator3.address);
//     expect(validators.length).to.equal(2);
//     expect(await nativeBridge.threshold()).to.equal(Math.ceil((2 * 2) / 3)); // 2
//   });

//     it("Should revert if non-owner tries to remove validator", async function () {
//       await expect(
//         nativeBridge.connect(nonValidator).removeValidator(validator1.address)
//       ).to.be.revertedWith("Ownable: caller is not the owner");
//     });

//     it("Should revert if removing non-existent validator", async function () {
//       await expect(
//         nativeBridge.connect(owner).removeValidator(nonValidator.address)
//       ).to.be.revertedWith("Validator not found");
//     });
//   });

//   describe("Signature Submission and Execution", function () {
//     let messageHash, signature1, signature2, userAddr, tokenType, tokenAddr;

//     beforeEach(async function () {
//       userAddr = ethers.getBytes(user.address);
//       tokenType = 0;
//       tokenAddr = ethers.ZeroAddress;
//       amount = ethers.parseEther("1");

//       const abiCoder = new AbiCoder();
//       const userBytes = ethers.getBytes(user.address);
//       const wrongUserBytes = ethers.getBytes(nonValidator.address);
//       // Khi tạo messageHash:
//       messageHash = ethers.keccak256(
//         abiCoder.encode(
//           ["bytes", "uint256", "uint8", "address"],
//           [userBytes, amount, tokenType, tokenAddr]
//         )
//       );

//       signature1 = await validator1.signMessage(getBytes(messageHash));
//       signature2 = await validator2.signMessage(getBytes(messageHash));

//       console.log("=== Signature Setup ===");
//       console.log("userAddr:", userAddr);
//       console.log("amount:", amount.toString());
//       console.log("tokenType:", tokenType);
//       console.log("tokenAddr:", tokenAddr);
//       console.log("messageHash:", messageHash);
//       console.log("signature1:", signature1);
//       console.log("signature2:", signature2);
//       console.log("=======================");
//     });

//     it("Should execute ERC20 unlock when threshold is met", async function () {
//     const unlockAmount = ethers.parseEther("1");
//     await mockERC20.transfer(nativeBridge.target, ethers.parseEther("10000"));

//     await mockERC20.connect(user).transfer(owner.address, await mockERC20.balanceOf(user.address));
//     const userBalanceBefore = await mockERC20.balanceOf(user.address);
//     console.log("User balance before:", userBalanceBefore.toString());

//     const tokenTypeERC20 = 1;
//     const tokenAddrERC20 = mockERC20.target;
//     const abiCoder = new AbiCoder();
//     const userBytes = ethers.getBytes(user.address);

//     const messageHashERC20 = ethers.keccak256(
//         abiCoder.encode(
//             ["bytes", "uint256", "uint8", "address"],
//             [userBytes, unlockAmount, tokenTypeERC20, tokenAddrERC20]
//         )
//     );

//     const signature1ERC20 = await validator1.signMessage(getBytes(messageHashERC20));
//     const signature2ERC20 = await validator2.signMessage(getBytes(messageHashERC20));

//     const tx1 = await nativeBridge.connect(validator1).submitSignature(
//         messageHashERC20,
//         signature1ERC20,
//         userBytes,
//         unlockAmount,
//         tokenTypeERC20,
//         tokenAddrERC20
//     );
//     await tx1.wait();

//     const tx2 = await nativeBridge.connect(validator2).submitSignature(
//         messageHashERC20,
//         signature2ERC20,
//         userBytes,
//         unlockAmount,
//         tokenTypeERC20,
//         tokenAddrERC20
//     );
//     await tx2.wait();

//     const userBalanceAfter = await mockERC20.balanceOf(user.address);
//     console.log("User balance after:", userBalanceAfter.toString());
//     expect(userBalanceAfter - userBalanceBefore).to.equal(unlockAmount);
// });

//     it("Should revert if non-validator submits signature", async function () {
//       const signature = await nonValidator.signMessage(getBytes(messageHash));
//       await expect(
//         nativeBridge.connect(nonValidator).submitSignature(
//           messageHash,
//           signature,
//           userAddr,
//           amount,
//           tokenType,
//           tokenAddr
//         )
//       ).to.be.revertedWith("Not validator");
//     });

//     it("Should revert if validator submits same signature twice", async function () {
//       await nativeBridge.connect(validator1).submitSignature(
//         messageHash,
//         signature1,
//         userAddr,
//         amount,
//         tokenType,
//         tokenAddr
//       );
//       await expect(
//         nativeBridge.connect(validator1).submitSignature(
//           messageHash,
//           signature1,
//           userAddr,
//           amount,
//           tokenType,
//           tokenAddr
//         )
//       ).to.be.revertedWith("Already signed");
//     });

//     it("Should revert if invalid signature is submitted", async function () {
//       const invalidSignature = await nonValidator.signMessage(getBytes(messageHash));
//       await expect(
//         nativeBridge.connect(validator1).submitSignature(
//           messageHash,
//           invalidSignature,
//           userAddr,
//           amount,
//           tokenType,
//           tokenAddr
//         )
//       ).to.be.revertedWith("Invalid signature");
//     });

//     it("Should revert if message data does not match messageHash", async function () {
//       const wrongUserBytes = ethers.getBytes(nonValidator.address);
//       await expect(
//         nativeBridge.connect(validator1).submitSignature(
//           messageHash,
//           signature1,
//           wrongUserBytes, // bytes 20
//           amount,
//           tokenType,
//           tokenAddr
//         )
//       ).to.be.revertedWith("Invalid message hash");
//     });

//     it("Should revert if insufficient ERC20 balance", async function () {
//       const tokenTypeERC20 = 1;
//       const tokenAddrERC20 = mockERC20.target;
//       const bigAmount = ethers.parseEther("1000"); // Vượt quá số dư
//       const abiCoder = new AbiCoder();
//       const userBytes = ethers.getBytes(user.address);
//       console.log("userBytes hex:", ethers.hexlify(userBytes)); // phải là 0x... 40 ký tự sau 0x
//       const messageHashERC20 = ethers.keccak256(
//         abiCoder.encode(
//           ["bytes", "uint256", "uint8", "address"],
//           [userBytes, bigAmount, tokenTypeERC20, tokenAddrERC20]
//         )
//       );
//       const signature1ERC20 = await validator1.signMessage(getBytes(messageHashERC20));
//       const signature2ERC20 = await validator2.signMessage(getBytes(messageHashERC20));

//       await nativeBridge.connect(validator1).submitSignature(
//         messageHashERC20,
//         signature1ERC20,
//         userBytes,
//         bigAmount,
//         tokenTypeERC20,
//         tokenAddrERC20
//       );

//       await expect(
//         nativeBridge.connect(validator2).submitSignature(
//           messageHashERC20,
//           signature2ERC20,
//           userBytes,
//           bigAmount,
//           tokenTypeERC20,
//           tokenAddrERC20
//         )
//       ).to.be.revertedWith("Insufficient ERC20 balance");
//     });
//   });

  // Các describe khác giữ nguyên hoặc mở lại khi cần test thêm
// });