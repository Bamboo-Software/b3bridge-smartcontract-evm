const { expect } = require("chai");
const { ethers } = require("hardhat");
const { AbiCoder } = require("ethers");
describe("NativeBridge", function () {
  console.log("Running NativeBridge tests...");
  let owner, user, other;
  let NativeBridge, nativeBridge;
  let MockERC20, erc20;
  let MockOFTV2, oftToken;
  let MockRouterClient, mockRouter;

  const minFee = ethers.parseEther("0.01");
  const maxFee = ethers.parseEther("0.1");

  beforeEach(async () => {
  [owner, user, other] = await ethers.getSigners();
  console.log("Signers:", { owner: owner.address, user: user.address, other: other.address });

  const minFee = ethers.parseEther("0.01");
  const maxFee = ethers.parseEther("0.1");
  console.log("minFee:", minFee.toString(), "maxFee:", maxFee.toString());

  const MockRouterClientFactory = await ethers.getContractFactory("MockCCIPRouter");
  mockRouter = await MockRouterClientFactory.deploy();
  await mockRouter.waitForDeployment();
  console.log("MockRouter deployed at:", mockRouter.target);

  const MockERC20Factory = await ethers.getContractFactory("MockERC20");
  erc20 = await MockERC20Factory.deploy("MockToken", "MTK", 18);
  await erc20.waitForDeployment();
  console.log("MockERC20 deployed at:", erc20.target);

  await erc20.mint(user.address, ethers.parseEther("1000"));
  console.log("Minted 1000 MTK to user:", user.address);


  const MockOFTV2Factory = await ethers.getContractFactory("MockOFT");
  oftToken = await MockOFTV2Factory.deploy("0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC");
  await oftToken.waitForDeployment();
  console.log("MockOFT deployed at:", oftToken.target);

  const NativeBridgeFactory = await ethers.getContractFactory("NativeBridge2");
  console.log('Deploying NativeBridge with params:', mockRouter.target, minFee.toString(), maxFee.toString());
  nativeBridge = await NativeBridgeFactory.deploy(
    mockRouter.target,
    minFee,
    maxFee
  );
  await nativeBridge.waitForDeployment();
  console.log("NativeBridge deployed at:", nativeBridge.target);

  await erc20.connect(user).approve(nativeBridge.target, ethers.parseEther("1000"));
  console.log("User approved NativeBridge to spend 1000 MTK");
});

  describe("Initialization", () => {
    it("should initialize min and max fees", async () => {
      expect(await nativeBridge.minCCIPFee()).to.equal(minFee);
      expect(await nativeBridge.maxCCIPFee()).to.equal(maxFee);
    });

    // it("should revert if minFee > maxFee on deploy", async () => {
    //   const NativeBridgeFactory = await ethers.getContractFactory("NativeBridge");
    //   await expect(
    //     NativeBridgeFactory.deploy(mockRouter.address, maxFee, minFee)
    //   ).to.be.revertedWith("minCCIPFee must be <= maxCCIPFee");
    // });
  });

  // describe("Setters for fees", () => {
  //   it("owner can update max fee >= min fee", async () => {
  //     const newMax = ethers.parseEther("0.1");
  //     await expect(nativeBridge.connect(owner).setMaxCCIPFee(newMax))
  //       .to.emit(nativeBridge, "MaxCCIPFeeUpdated").withArgs(newMax);

  //     expect(await nativeBridge.maxCCIPFee()).to.equal(newMax);
  //   });

  //   it("should revert when non-owner sets fees", async () => {
  //     await expect(nativeBridge.connect(user).setMaxCCIPFee(minFee))
  //       .to.be.revertedWith("Ownable: caller is not the owner");
  //   });

  //   // it("should revert if max fee < min fee", async () => {
  //   //   await expect(nativeBridge.connect(owner).setMaxCCIPFee(minFee.sub(1)))
  //   //     .to.be.revertedWith("Max fee must be >= min fee");
  //   // });

  //   it("owner can update min fee <= max fee", async () => {
  //     const newMin = ethers.parseEther("0.005");
  //     await expect(nativeBridge.connect(owner).setMinCCIPFee(newMin))
  //       .to.emit(nativeBridge, "MinCCIPFeeUpdated").withArgs(newMin);
  //     expect(await nativeBridge.minCCIPFee()).to.equal(newMin);
  //   });

    // it("should revert if min fee > max fee", async () => {
    //   await expect(nativeBridge.connect(owner).setMinCCIPFee(maxFee.add(1)))
    //     .to.be.revertedWith("Min fee must be <= max fee");
    // });
  // });

  describe("Lock Native", () => {
    // it("should revert if amountToBridge = 0", async () => {
    //   await expect(nativeBridge.connect(user).lockNative(100, ethers.encodeBytes32String("0x00").slice(0, 20), 0, { value: minFee }))
    //     .to.be.revertedWith("Amount to bridge must be > 0");
    // });

    // // it("should revert if destAddress length != 20", async () => {
    // //   await expect(nativeBridge.connect(user).lockNative(100, "0x1234", 1, { value: minFee.add(100) }))
    // //     .to.be.revertedWith("Destination address must be 20 bytes");
    // // });

    // it("should revert if fee out of range", async () => {
    //   // fee less than minCCIPFee
    //   await expect(nativeBridge.connect(user).lockNative(ethers.parseEther("1"), ethers.hexlify(ethers.randomBytes(20)), 1, {
    //     value: ethers.parseEther("1") // amountToBridge=1 ether, fee=0, so fee < minFee
    //   })).to.be.revertedWith("Fee out of range");
    // });

    // it("should emit LockedNative and call ccipSend", async () => {
    //   // Setup mockRouter to return fee <= actual fee
    //   await mockRouter.setFee(minFee);

    //   const amount = ethers.parseEther("1");
    //   const fee = minFee;

    //   // send value = amount + fee
    //   const destAddress = ethers.hexlify(ethers.randomBytes(20));
    //   await expect(nativeBridge.connect(user).lockNative(1, destAddress, amount, { value: amount.add(fee) }))
    //     .to.emit(nativeBridge, "LockedNative")
    //     .withArgs(user.address, amount, 1, destAddress);
    // });
  });

  describe("Lock ERC20", () => {
    // it("should revert if amount = 0", async () => {
    //   await expect(nativeBridge.connect(user).lockERC20(erc20.target, 0, 1, ethers.hexlify(ethers.randomBytes(20)), { value: minFee }))
    //     .to.be.revertedWith("Amount must be > 0");
    // });

    // it("should revert if token address is 0", async () => {
    //   await expect(nativeBridge.connect(user).lockERC20("0x0000000000000000000000000000000000000000", 10, 1, ethers.hexlify(ethers.randomBytes(20)), { value: minFee }))
    //     .to.be.revertedWith("Invalid token address");
    // });

    // it("should revert if destAddress length != 20", async () => {
    //   await expect(nativeBridge.connect(user).lockERC20(erc20.target, 10, 1, "0x1234", { value: minFee }))
    //     .to.be.revertedWith("Destination address must be 20 bytes");
    // });

    it("should lock tokens and emit LockedERC20", async () => {
      await mockRouter.setFee(minFee);

      const amount = ethers.parseEther("10");
      const fee = minFee;
      const destAddress = ethers.hexlify(ethers.randomBytes(20));

      // User approve is done in beforeEach
      await expect(nativeBridge.connect(user).lockERC20(erc20.target, amount, 1, destAddress, { value: fee }))
        .to.emit(nativeBridge, "LockedERC20")
        .withArgs(user.address, erc20.address, amount, 1, destAddress);

      // Check contract balance increased
      expect(await erc20.balanceOf(nativeBridge.address)).to.equal(amount);
    });
  });

  describe("Lock OFT", () => {
    it("should revert if amountToBridge = 0", async () => {
      await expect(nativeBridge.connect(user).lockOFT(oftToken.target, 0, 1, ethers.hexlify(ethers.randomBytes(20)), { value: minFee }))
        .to.be.revertedWith("Amount must be > 0");
    });

    it("should revert if destAddress length != 20", async () => {
      await expect(nativeBridge.connect(user).lockOFT(oftToken.target, 10, 1, "0x1234", { value: minFee }))
        .to.be.revertedWith("Destination address must be 20 bytes");
    });

    it("should revert if fee out of range", async () => {
      await expect(nativeBridge.connect(user).lockOFT(oftToken.target, 10, 1, ethers.hexlify(ethers.randomBytes(20)), { value: 0 }))
        .to.be.revertedWith("Fee out of range");
    });

    // it("should emit LockedERC20 and call sendFrom on OFT token", async () => {
    //   const amount = ethers.parseEther("10");
    //   const fee = minFee;

    //   // Setup mock to accept sendFrom call
    //   await oftToken.setExpectedSendFromParams(user.address, 1, ethers.encodeBytes32String("0x00"), amount);

    //   const destAddress = ethers.hexlify(ethers.randomBytes(20));
    //   await expect(nativeBridge.connect(user).lockOFT(oftToken.target, amount, 1, destAddress, { value: fee }))
    //     .to.emit(nativeBridge, "LockedERC20")
    //     .withArgs(user.address, oftToken.target, amount, 1, destAddress);
    // });
  });

  describe("CCIP Receive (_ccipReceive)", () => {
    it("should unlock native tokens", async () => {
  // Send some native balance to contract
  await owner.sendTransaction({ to: nativeBridge.target, value: ethers.parseEther("10") });

  const userAddress = user.address;
  const amount = ethers.parseEther("1");
  const tokenType = 0;
  const tokenAddr = "0x0000000000000000000000000000000000000000";
  const messageId = ethers.hexlify(ethers.randomBytes(32));

  const abiCoder = new AbiCoder();
  const data = abiCoder.encode(
    ["address", "uint256", "uint8", "address"],
    [userAddress, amount, tokenType, tokenAddr]
  );

  const message = {
    messageId: messageId,
    sourceChainSelector: 1,          // <=== Phải có giá trị số, ví dụ 1
    data: data,
    sender: owner.address, 
    receiver: nativeBridge.target,   // hoặc userAddress tùy contract
    tokenAmounts: [],  
     destTokenAmounts: [],              // giả sử không gửi token nào kèm
    extraArgs: "0x"
  };

  await expect(nativeBridge.connect(owner).test_ccipReceive(message))
    .to.emit(nativeBridge, "UnlockedNative")
    .withArgs(userAddress, amount);
});

it("should unlock ERC20 tokens", async () => {
  // Mint tokens to contract for unlock
  const amount = ethers.parseEther("5");
  await erc20.mint(nativeBridge.target, amount);

  const userAddress = user.address;
  const tokenType = 1; // ERC20 token type
  const messageId = ethers.encodeBytes32String("msg2");

  const abiCoder = new AbiCoder();
  const data = abiCoder.encode(
    ["address", "uint256", "uint8", "address"],
    [userAddress, amount, tokenType, erc20.target]
  );

  // Chuẩn bị message dạng Client.Any2EVMMessage theo struct contract yêu cầu
  const message = {
    messageId: messageId,
    data: data,
    // Bổ sung các trường bắt buộc khác, ví dụ:
    sourceChainSelector: 1,       // giả định chain id nguồn là 1
    sender: ethers.ZeroAddress,   // giả định sender là địa chỉ zero (hoặc sửa cho phù hợp)
    receiver: nativeBridge.target,
    destChainSelector: 1,         // giả định chain id đích là 1
    destTokenAmounts: [],         // ví dụ chưa dùng token amounts, để mảng rỗng
    extraArgs: "0x",              // empty bytes
  };

  await expect(nativeBridge.connect(owner).test_ccipReceive(message))
    .to.emit(nativeBridge, "UnlockedERC20")
    .withArgs(userAddress, erc20.target, amount);
});

it("should revert if message processed twice", async () => {
  // Chuyển native token vào contract để có tiền trả khi unlock
  await owner.sendTransaction({ to: nativeBridge.target, value: ethers.parseEther("10") });

  const messageId = ethers.encodeBytes32String("msg3");
  const abiCoder = new AbiCoder();
  const data = abiCoder.encode(
    ["address", "uint256", "uint8", "address"],
    [user.address, ethers.parseEther("1"), 0, "0x0000000000000000000000000000000000000000"]
  );

  const message = {
    messageId: messageId,
    data: data,
    sourceChainSelector: 1,
    sender: ethers.ZeroAddress,
    receiver: nativeBridge.target,
    destChainSelector: 1,
    destTokenAmounts: [],
    extraArgs: "0x"
  };

  await nativeBridge.connect(owner).test_ccipReceive(message);

  await expect(nativeBridge.connect(owner).test_ccipReceive(message))
    .to.be.revertedWith("Message already processed");
});

    it("should revert on unsupported tokenType", async () => {
  const abiCoder = new AbiCoder();
  const data = abiCoder.encode(
    ["address", "uint256", "uint8", "address"],
    [user.address, ethers.parseEther("1"), 99, ethers.ZeroAddress]
  );

  const message = {
    messageId: ethers.encodeBytes32String("msg4"),
    data,
    sourceChainSelector: 1,             
    sender: ethers.ZeroAddress,
    receiver: nativeBridge.target,
    destChainSelector: 1,
    destTokenAmounts: [],           
    extraArgs: "0x"
  };

  await expect(nativeBridge.connect(owner).test_ccipReceive(message))
    .to.be.revertedWith("Unsupported token type");
});

  });

  describe("Rescue", () => {
    // it("owner can rescue ERC20 tokens", async () => {
    //   // Mint tokens to contract
    //   const amount = ethers.parseEther("0.1");
    //   await erc20.mint(nativeBridge.target, amount);

    //   await expect(nativeBridge.connect(owner).rescueERC20(erc20.target, amount))
    //     .to.emit(nativeBridge, "RescueERC20")
    //     .withArgs(erc20.target, amount);

    //   expect(await erc20.balanceOf(owner.address)).to.equal(amount);
    // });

    it("should revert if non-owner rescues tokens", async () => {
      await expect(nativeBridge.connect(user).rescueERC20(erc20.target, 1))
        .to.be.revertedWith("Ownable: caller is not the owner");
    });

    // it("owner can rescue native tokens", async () => {
    //   // Send native to contract
    //   const amount = ethers.parseEther("0.1");
    //   await owner.sendTransaction({ to: nativeBridge.target, value: amount });

    //   await expect(() => nativeBridge.connect(owner).rescueNative(amount))
    //     .to.changeEtherBalances([nativeBridge, owner], [amount.mul(-1), amount]);

    //   await expect(nativeBridge.connect(owner).rescueNative(amount.add(1)))
    //     .to.be.revertedWith("Insufficient native balance");
    // });
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
