const { ethers } = require("hardhat");

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log("Deploying contracts with account:", deployer.address);

  const ccipRouterAddress = "0x0BF3dE8c5D3e8A2B34D2BEeB17ABfCeBaf363A59";
  const link = "0x779877A7B0D9E8603169DdbD7836e478b4624789";
  const validators = [deployer.address];
  const threshold = 1;

  const NativeBridge = await ethers.getContractFactory("NativeBridge");
  const nativeBridge = await NativeBridge.deploy(
    ccipRouterAddress,
    validators,
    threshold,
    link
  );
  await nativeBridge.waitForDeployment();
  console.log("NativeBridge deployed to:", await nativeBridge.getAddress());

  // Tạo tokenId từ keccak256("USDC")
  const tokenId = ethers.keccak256(ethers.toUtf8Bytes("USDC"));
  console.log("TokenId for USDC:", tokenId);

  const usdcSepoliaAddress = "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238";

  // Map chiều tokenAddress -> tokenId (nếu cần)
  const tx1 = await nativeBridge.setTokenAddressToId(usdcSepoliaAddress, tokenId);
  await tx1.wait();
  console.log(`Mapped token address ${usdcSepoliaAddress} to tokenId ${tokenId} (tx: ${tx1.hash})`);

  // Map chiều tokenId -> tokenAddress (bắt buộc để nhận token trong _ccipReceive)
  const tx2 = await nativeBridge.setTokenMapping(tokenId, usdcSepoliaAddress);
  await tx2.wait();
  console.log(`Mapped tokenId ${tokenId} to token address ${usdcSepoliaAddress} (tx: ${tx2.hash})`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
