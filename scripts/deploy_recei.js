const { ethers } = require("hardhat");

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log("Deploying contracts with account:", deployer.address);

  const ccipRouterAddress = "0xAba60dA7E88F7E8f5868C2B6dE06CB759d693af0";

  // Danh sách validator
  const validators = [deployer.address];
  const threshold = 1;

  const NativeBridge = await ethers.getContractFactory("CCIPReceiverExample");
  const nativeBridge = await NativeBridge.deploy(
    ccipRouterAddress,
  );
  await nativeBridge.waitForDeployment();
  console.log("NativeBridge deployed to:", await nativeBridge.getAddress());
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
