const { run } = require("hardhat");


async function main() {

  const address = "0x282884fB2d9365652178656EF6955dFAB1481F5f";

  const ccipRouterAddress = "0x80226fc0Ee2b096224EeAc085Bb9a8cba1146f7D";
  const link = "0x514910771AF9Ca656af840dff83E8264EcF986CA";
  const validators = ["0xBdA83db19c92F5CD38095a241A3636ea58Ee4b45"];
  const threshold = 1;

  console.log("Verifying contract at:", address);

  try {
    await run("verify:verify", {
      address: address,
      constructorArguments: [ccipRouterAddress, validators, threshold, link],
    });
    console.log("Verification successful!");
  } catch (error) {
    console.error("Verification failed:", error);
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
