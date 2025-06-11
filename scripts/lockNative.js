const { ethers } = require("hardhat");

async function main() {
  const [user] = await ethers.getSigners();

  const nativeBridgeAddress = "0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9";
  const NativeBridge = await ethers.getContractFactory("NativeBridge");
  const nativeBridge = await NativeBridge.attach(nativeBridgeAddress);

  const destinationChainId = 137;
  const destAddress = ethers.encodeBytes32String("0x1234...");

  const tx = await nativeBridge.lockNative(destinationChainId, destAddress, {
    value: ethers.parseEther("0.1"),
  });

  await tx.wait();
  console.log("lockNative sent!");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
