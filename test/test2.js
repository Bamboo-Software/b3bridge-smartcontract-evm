const { expect } = require("chai");
const { ethers } = require("hardhat");
const { AbiCoder } = require("ethers");

describe("NativeBridge", function () {
  let owner, validator1, validator2, validator3, nonValidator, user;
  let mockERC20, mockRouter, nativeBridge, amount;

  beforeEach(async function () {
    const signers = await ethers.getSigners();
    owner = signers[0];
    validator1 = signers[1];
    validator2 = signers[2];
    validator3 = signers[3];
    nonValidator = signers[4];
    user = signers[5];

    amount = ethers.parseEther("10");

    // Deploy MockERC20
    const MockERC20Factory = await ethers.getContractFactory("MockERC20");
    mockERC20 = await MockERC20Factory.deploy("MockToken", "MTK", 18);
    await mockERC20.waitForDeployment();

    // Deploy Mock Router
    const MockRouterFactory = await ethers.getContractFactory("MockCCIPRouter");
    mockRouter = await MockRouterFactory.deploy();
    await mockRouter.waitForDeployment();

    // Deploy NativeBridge với mockRouter
    const NativeBridge = await ethers.getContractFactory("NativeBridge");
    nativeBridge = await NativeBridge.deploy(
      mockRouter.target,
      [validator1.address, validator2.address, validator3.address],
      3
    );
    await nativeBridge.waitForDeployment();

    // Fund NativeBridge contract with 10 ETH
    const tx = await owner.sendTransaction({
      to: nativeBridge.target,
      value: ethers.parseEther("10"),
    });
    await tx.wait();

    // Mint token cho user trước khi approve và lock
    await mockERC20.mint(user.address, amount);

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

  describe("Lock Native", () => {
    const destChainSelector = 16015286601757825753n;
    const desWalletAddress = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e";

    it("should revert if amountToBridge = 0", async () => {
      const destAddress = ethers.hexlify(ethers.randomBytes(20));
      await expect(
        nativeBridge.connect(user).lockNative(
          destChainSelector,
          destAddress,
          desWalletAddress,
          0,
          { value: ethers.parseEther("0.01") }
        )
      ).to.be.revertedWith("Amount to bridge must be > 0");
    });

    it("should revert if destAddress length != 20", async () => {
      const shortDestAddress = ethers.hexlify(ethers.randomBytes(2));
      await expect(
        nativeBridge.connect(user).lockNative(
          destChainSelector,
          shortDestAddress,
          desWalletAddress,
          ethers.parseEther("1"),
          { value: ethers.parseEther("1.01") }
        )
      ).to.be.revertedWith("Destination address must be 20 bytes");
    });

    it("should emit LockedNative and call ccipSend", async () => {
      const amount = ethers.parseEther("1");
      const fee = ethers.parseEther("0.01");
      const destAddress = ethers.hexlify(ethers.randomBytes(20));
      console.log("LockNative params:", {
        destChainSelector,
        destAddress,
        desWalletAddress,
        amount: amount.toString(),
        fee: fee.toString(),
        msgValue: (amount + fee).toString(),
      });
      await expect(
        nativeBridge.connect(user).lockNative(
          destChainSelector,
          destAddress,
          desWalletAddress,
          amount,
          { value: amount + fee }
        )
      )
        .to.emit(nativeBridge, "LockedNative")
        .withArgs(user.address, amount, destChainSelector, destAddress, desWalletAddress);
    });
  });

  describe("Lock ERC20", () => {
    const destChainSelector = 16015286601757825753n;
    const destAddress = ethers.hexlify(ethers.randomBytes(20));
    const desWalletAddress = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e";

    it("should revert if amount = 0", async () => {
      await expect(
        nativeBridge.connect(user).lockERC20(
          mockERC20.target,
          0,
          1,
          ethers.hexlify(ethers.randomBytes(20)),
          desWalletAddress
        )
      ).to.be.revertedWith("Amount must be > 0");
    });

    it("should revert if token address is 0", async () => {
      const zero = "0x0000000000000000000000000000000000000000";
      await expect(
        nativeBridge.connect(user).lockERC20(
          zero,
          10,
          1,
          ethers.hexlify(ethers.randomBytes(20)),
          ethers.hexlify(ethers.randomBytes(20))
        )
      ).to.be.revertedWith("Invalid token address");
    });

    it("should revert if destAddress length != 20", async () => {
      await expect(
        nativeBridge.connect(user).lockERC20(
          mockERC20.target,
          1,
          1,
          "0x1234",
          ethers.hexlify(ethers.randomBytes(20))
        )
      ).to.be.revertedWith("Destination address must be 20 bytes");
    });

    it("should return a valid CCIP fee", async () => {
      const abiCoder = new AbiCoder();
      const messagePayload = abiCoder.encode(
        ["address", "uint256", "uint8", "address"],
        [desWalletAddress, amount, 1, ethers.ZeroAddress]
      );
      const extraArgs = "0x";
      const evmMessage = {
        receiver: ethers.getBytes(desWalletAddress),
        data: messagePayload,
        tokenAmounts: [],
        feeToken: ethers.ZeroAddress,
        extraArgs: extraArgs
      };
      const fee = await nativeBridge.getFeeForMessage(destChainSelector, evmMessage);
      console.log("Estimated CCIP fee:", ethers.formatEther(fee));
      expect(fee).to.be.gt(0);
    });

    it("should lock tokens and emit LockedERC20", async () => {
      // Mint token cho user trước khi approve và lock
      await mockERC20.mint(user.address, amount);
      await mockERC20.connect(user).approve(nativeBridge.target, amount);
      const fee = ethers.parseEther("0.01");
      console.log("lockERC20 params:");
      console.log("mockERC20.target:", mockERC20.target);
      console.log("amount:", amount.toString());
      console.log("destChainSelector:", destChainSelector);
      console.log("destAddress:", destAddress);
      console.log("desWalletAddress:", desWalletAddress);
      console.log("fee (msg.value):", fee.toString());
      await expect(
        nativeBridge.connect(user).lockERC20(
          mockERC20.target,
          amount,
          destChainSelector,
          destAddress,
          desWalletAddress,
          { value: fee }
        )
      )
        .to.emit(nativeBridge, "LockedERC20")
        .withArgs(
          user.address,
          mockERC20.target,
          amount,
          destChainSelector,
          destAddress,
          desWalletAddress
        );
      expect(await mockERC20.balanceOf(nativeBridge.target)).to.equal(amount);
    });
  });

  // Các describe khác giữ nguyên hoặc mở lại khi cần test thêm

  describe("Rescue", () => {
    it("should revert if non-owner rescues tokens", async () => {
      await expect(
        nativeBridge.connect(user).rescueERC20(mockERC20.target, 1)
      ).to.be.revertedWith("Ownable: caller is not the owner");
    });
  });

  describe("Pause / Unpause", () => {
    it("owner can pause and unpause", async () => {
      await nativeBridge.connect(owner).pause();
      expect(await nativeBridge.paused()).to.be.true;
      await nativeBridge.connect(owner).unpause();
      expect(await nativeBridge.paused()).to.be.false;
    });

    it("non-owner cannot pause/unpause", async () => {
      await expect(nativeBridge.connect(user).pause())
        .to.be.revertedWith("Ownable: caller is not the owner");
      await expect(nativeBridge.connect(user).unpause())
        .to.be.revertedWith("Ownable: caller is not the owner");
    });
  });
});
