#pragma once

#include <iostream>
#include <utility>

#include <crypto++/cryptlib.h>
#include <crypto++/dh.h>
#include <crypto++/dh2.h>
#include <crypto++/integer.h>
#include <crypto++/nbtheory.h>
#include <crypto++/osrng.h>

#include "../../include/drivers/cli_driver.hpp"
#include "../../include/drivers/crypto_driver.hpp"
#include "../../include/drivers/db_driver.hpp"
#include "../../include/drivers/network_driver.hpp"
#include "config.hpp"
#include "keyloaders.hpp"
#include "concurrent_queue.hpp"

typedef struct SecureNetwork
{
    std::shared_ptr<NetworkDriver> network_driver;
    CryptoPP::SecByteBlock AES_key;
    CryptoPP::SecByteBlock HMAC_key;
} SecureNetwork;

class ServerClient
{
public:
    ServerClient(ServerConfig server_config);
    void run(int port);
    bool HandleConnection(std::shared_ptr<NetworkDriver> network_driver,
                          std::shared_ptr<CryptoDriver> crypto_driver);
    std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock>
    HandleKeyExchange(std::shared_ptr<NetworkDriver> network_driver,
                      std::shared_ptr<CryptoDriver> crypto_driver);
    void
    HandleLogin(std::shared_ptr<NetworkDriver> network_driver,
                std::shared_ptr<CryptoDriver> crypto_driver, std::string id,
                std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys);
    void HandleRegister(
        std::shared_ptr<NetworkDriver> network_driver,
        std::shared_ptr<CryptoDriver> crypto_driver, std::string id,
        std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys);

private:
    ServerConfig server_config;
    std::shared_ptr<CLIDriver> cli_driver;
    std::shared_ptr<DBDriver> db_driver;
    std::map<std::string, SecureNetwork> networkMap;
    ConcurrentQueue<std::vector<unsigned char>> msg_q;

    CryptoPP::DSA::PrivateKey DSA_signing_key;
    CryptoPP::DSA::PublicKey DSA_verification_key;

    bool SendMessage();
    void ListenForConnections(int port);
    void Reset(std::string _);
    void Users(std::string _);

    std::string SaltAndPassword(
        std::shared_ptr<NetworkDriver> network_driver,
        std::shared_ptr<CryptoDriver> crypto_driver,
        std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys,
        std::string salt);

    void Verify2FA(
        std::shared_ptr<NetworkDriver> network_driver,
        std::shared_ptr<CryptoDriver> crypto_driver,
        std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys,
        std::string prg_seed);

    void SendCertificate(
        std::shared_ptr<NetworkDriver> network_driver,
        std::shared_ptr<CryptoDriver> crypto_driver,
        std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys,
        std::string id);
};
