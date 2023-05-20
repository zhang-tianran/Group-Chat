#pragma once

#include <iostream>

#include <crypto++/cryptlib.h>
#include <crypto++/dh.h>
#include <crypto++/dh2.h>
#include <crypto++/integer.h>
#include <crypto++/nbtheory.h>
#include <crypto++/osrng.h>

#include "../../include/drivers/cli_driver.hpp"
#include "../../include/drivers/crypto_driver.hpp"
#include "../../include/drivers/network_driver.hpp"
#include "config.hpp"
#include "keyloaders.hpp"

typedef struct UserKeys
{
  CryptoPP::DSA::PublicKey DSA_remote_verification_key;
  CryptoPP::SecByteBlock AES_key;
  CryptoPP::SecByteBlock HMAC_key;
} UserKeys;

class UserClient
{
public:
  UserClient(std::shared_ptr<NetworkDriver> network_driver,
             std::shared_ptr<CryptoDriver> crypto_driver,
             UserConfig user_config);
  void run();

  // User2Server
  std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> HandleServerKeyExchange();
  void HandleLoginOrRegister(std::string input);
  void DoLoginOrRegister(std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys, std::string input);

  // User2User
  /// send
  void SendMsg(std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys,
               std::vector<unsigned char> userData,
               MessageType::Action action,
               std::string recipient);
  void GroupChange(std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys,
                   std::string groupID,
                   std::string userID,
                   bool is_leaving);
  /// receive
  void HandleReceiveMessage(std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys,
                            std::vector<unsigned char> serverData);
  /// key exchange
  bool DoKeyExchange(std::string userID, std::pair<SecByteBlock, SecByteBlock> keys);
  void SendUserKeyExchange(std::string recipientID, std::pair<SecByteBlock, SecByteBlock> keys);
  void ReceiveUserKeyExchange(std::vector<unsigned char> otherPubVal, std::pair<SecByteBlock, SecByteBlock> keys);

private:
  std::string id;
  Certificate_Message certificate;

  std::map<std::string, std::tuple<DH, SecByteBlock, SecByteBlock>> myDHinfo;
  std::map<std::string, UserKeys> keyMap;
  std::map<std::string, std::set<std::string>> groupMap;

  UserConfig user_config;
  std::shared_ptr<CLIDriver> cli_driver;
  std::shared_ptr<CryptoDriver> crypto_driver;
  std::shared_ptr<NetworkDriver> network_driver;

  CryptoPP::DSA::PrivateKey DSA_signing_key;
  CryptoPP::DSA::PublicKey DSA_verification_key;
  CryptoPP::DSA::PublicKey DSA_server_verification_key;
  CryptoPP::SecByteBlock prg_seed;

  void
  ReceiveThread(std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys);
  void
  SendThread(std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys);
};
