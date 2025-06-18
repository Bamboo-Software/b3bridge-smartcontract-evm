import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";
import * as dotenv from "dotenv";

dotenv.config();
const config = {
  solidity: {
    version: "0.8.20",
    settings: {
      optimizer: {
        enabled: true,
        runs: 100,
      },
      evmVersion: "paris",
    },
  },
  networks: {
    sepolia: {
      url: `https://sepolia.infura.io/v3/${process.env.INFURA_API_KEY}`,
      accounts: [process.env.PRIVATE_KEY!],
    },
    ethereum: {
      url: `https://mainnet.infura.io/v3/${process.env.INFURA_API_KEY}`,
      chainId: 1,
      accounts: [process.env.PRIVATE_KEY!],
    },
    bsc: {
      url: process.env.BSC_RPC_URL,
      chainId: 56,
      accounts: [process.env.PRIVATE_KEY!],
    },
    sei: {
      url: process.env.SEI_RPC_URL,
      chainId: 1328,
      accounts: [process.env.PRIVATE_KEY!],
    },
    localhost: {
      url: process.env.LOCALHOST_RPC_URL,
    },
  },
  etherscan: {
    apiKey: {
      sepolia: process.env.ETHERSCAN_API_KEY_SEPOLIA,
      bsc: process.env.ETHERSCAN_API_KEY_BSC,
      sei: process.env.ETHERSCAN_API_KEY_SEI,
    },
    customChains: [
      {
        network: "sei",
        chainId: 1328,
        urls: {
          apiURL: process.env.SEI_API_URL,
          browserURL: process.env.SEI_BROWSER_URL,
        },
      },
    ],
  },
};

export default config;
