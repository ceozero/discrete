// Copyright (c) 2026, The Discrete developers
//
// This file is part of Discrete.
//
// Discrete is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Discrete is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with Discrete. If not, see <http://www.gnu.org/licenses/>.

#include <cstring>
#include <fstream>
#include <iostream>
#include <string>

#include "Common/SecureMemory.h"
#include "Common/StringTools.h"
#include "CryptoNoteConfig.h"
#include "Logging/ConsoleLogger.h"
#include "Mnemonics/electrum-words.h"
#include "PqAddress.h"
#include "Wallet/MiningKeyLoader.h"
#include "Wallet/PqWallet.h"
#include "crypto/crypto-util.h"
#include "crypto_pq/PqSeed.h"

namespace {

void printUsage(const char* prog) {
  std::cerr << "Usage:\n"
            << "  " << prog << " --generate <output_json_path> [--wallet-file <path> --wallet-password <pwd>] [--from-seed <hex32>] [--testnet]\n"
            << "  " << prog << " --export-wallet <wallet_path> --wallet-password <pwd> <output_json_path> [--testnet]\n";
}

bool writeKeyJson(const std::string& outPath, const CryptoPQ::SeedMaster& seed, bool testnet) {
  CryptoNote::PqWalletKeys keys = CryptoNote::derivePqWalletKeys(seed);
  Tools::SecretLock lockKeys(&keys, sizeof(keys));

  Crypto::SecretKey seedKey;
  Tools::SecretLock lockSeedKey(&seedKey, sizeof(seedKey));
  std::memcpy(seedKey.data, seed.data(), sizeof(seedKey.data));

  std::string mnemonic;
  Crypto::ElectrumWords::bytes_to_words(seedKey, mnemonic, "English");

  CryptoNote::PqAddress addr = CryptoNote::pqWalletAddress(
      keys, CryptoNote::parameters::CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX);
  std::string pqAddrStr = CryptoNote::encodePqAddress(addr, CryptoNote::pqBech32Hrp(testnet));

  std::string seedHex = Common::toHex(seed.data(), seed.size());
  std::string spendPubHex = Common::toHex(keys.spendPub.data(), keys.spendPub.size());
  std::string spendSkHex = Common::toHex(keys.spendSk.data(), keys.spendSk.size());
  std::string viewPubHex = Common::toHex(keys.viewPub.data(), keys.viewPub.size());

  std::ofstream out(outPath, std::ios::out | std::ios::trunc);
  if (!out) {
    std::cerr << "Error: cannot open output file: " << outPath << "\n";
    return false;
  }

  out << "{\n"
      << "  \"key_epoch\": 1,\n"
      << "  \"seed_master\": \"" << seedHex << "\",\n"
      << "  \"mnemonic\": \"" << mnemonic << "\",\n"
      << "  \"hot_spend_pub\": \"" << spendPubHex << "\",\n"
      << "  \"hot_spend_sk\": \"" << spendSkHex << "\",\n"
      << "  \"spend_pub\": \"" << spendPubHex << "\",\n"
      << "  \"spend_sk\": \"" << spendSkHex << "\",\n"
      << "  \"view_pub\": \"" << viewPubHex << "\",\n"
      << "  \"pq_address\": \"" << pqAddrStr << "\"\n"
      << "}\n";
  out.flush();

  if (!seedHex.empty()) sodium_memzero(&seedHex[0], seedHex.size());
  if (!spendSkHex.empty()) sodium_memzero(&spendSkHex[0], spendSkHex.size());
  if (!mnemonic.empty()) sodium_memzero(&mnemonic[0], mnemonic.size());

  return out.good();
}

}  // namespace

int main(int argc, char* argv[]) {
  std::string outPath;
  std::string walletFile;
  std::string walletPassword;
  std::string seedHex;
  bool generate = false;
  bool exportWallet = false;
  bool testnet = false;

  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg == "--generate" && i + 1 < argc) {
      generate = true;
      outPath = argv[++i];
    } else if (arg == "--export-wallet" && i + 1 < argc) {
      exportWallet = true;
      walletFile = argv[++i];
    } else if (arg == "--wallet-file" && i + 1 < argc) {
      walletFile = argv[++i];
    } else if (arg == "--wallet-password" && i + 1 < argc) {
      walletPassword = argv[++i];
    } else if (arg == "--from-seed" && i + 1 < argc) {
      seedHex = argv[++i];
    } else if (arg == "--testnet") {
      testnet = true;
    } else if (arg == "--help" || arg == "-h") {
      printUsage(argv[0]);
      return 0;
    } else if (outPath.empty() && !arg.empty() && arg[0] != '-') {
      outPath = arg;
    } else {
      std::cerr << "Unknown or incomplete argument: " << arg << "\n";
      printUsage(argv[0]);
      return 1;
    }
  }

  if ((!generate && !exportWallet) || outPath.empty()) {
    printUsage(argv[0]);
    return 1;
  }

  CryptoPQ::SeedMaster seed{};
  Tools::SecretLock lockSeed(seed.data(), seed.size());

  try {
    if (!walletFile.empty()) {
      Logging::ConsoleLogger logger(Logging::WARNING);
      Crypto::SecretKey secret = CryptoNote::loadMiningSpendSecret(walletFile, walletPassword, logger);
      Tools::SecretLock lockSecret(&secret, sizeof(secret));
      seed = CryptoNote::pqSeedMasterFromSpendSecret(secret);
    } else if (!seedHex.empty()) {
      size_t sz = 0;
      if (!Common::fromHex(seedHex, seed.data(), seed.size(), sz) || sz != seed.size()) {
        std::cerr << "Error: --from-seed requires a 64-char (32-byte) hex seed\n";
        return 1;
      }
    } else {
      seed = CryptoNote::generatePqSeedMaster();
    }

    if (!writeKeyJson(outPath, seed, testnet)) {
      return 1;
    }
  } catch (const std::exception& e) {
    std::cerr << "Error: " << e.what() << "\n";
    return 1;
  }

  return 0;
}
