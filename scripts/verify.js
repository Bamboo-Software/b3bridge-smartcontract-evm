const { run } = require("hardhat");


async function main() {

  const address = "0x300C0A8514864fd23DA2E6fBF916A693F6082589";

  const ccipRouterAddress = "0x0BF3dE8c5D3e8A2B34D2BEeB17ABfCeBaf363A59";
  const link = "0x779877A7B0D9E8603169DdbD7836e478b4624789"
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
