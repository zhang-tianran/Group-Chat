#include <cmath>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <string>
#include <sys/ioctl.h>

#include <boost/asio.hpp>
#include <boost/lexical_cast.hpp>

#include "../../include-shared/constants.hpp"
#include "../../include-shared/keyloaders.hpp"
#include "../../include-shared/logger.hpp"
#include "../../include-shared/messages.hpp"
#include "../../include-shared/util.hpp"
#include "../../include/drivers/repl_driver.hpp"
#include "../../include/pkg/server.hpp"
#include "../../include/pkg/user.hpp"

/**
 * Constructor
 */
ServerClient::ServerClient(ServerConfig server_config)
{
  // Initialize cli driver.
  this->cli_driver = std::make_shared<CLIDriver>();
  this->cli_driver->init();

  // Initialize database driver.
  this->db_driver = std::make_shared<DBDriver>();
  this->db_driver->open(server_config.server_db_path);
  this->db_driver->init_tables();

  // Load server keys.
  try
  {
    LoadDSAPrivateKey(server_config.server_signing_key_path,
                      this->DSA_signing_key);
    LoadDSAPublicKey(server_config.server_verification_key_path,
                     this->DSA_verification_key);
  }
  catch (CryptoPP::FileStore::OpenErr)
  {
    this->cli_driver->print_warning(
        "Could not find server keys, generating them instead.");
    CryptoDriver crypto_driver;
    auto keys = crypto_driver.DSA_generate_keys();
    this->DSA_signing_key = keys.first;
    this->DSA_verification_key = keys.second;
    SaveDSAPrivateKey(server_config.server_signing_key_path,
                      this->DSA_signing_key);
    SaveDSAPublicKey(server_config.server_verification_key_path,
                     this->DSA_verification_key);
  }
}

/**
 * Run the server on the given port. First initializes the CLI and database,
 * then starts listening for connections.
 */
void ServerClient::run(int port)
{
  // Start listener thread
  std::thread listener_thread(&ServerClient::ListenForConnections, this, port);
  listener_thread.detach();

  // Start sender thread
  std::thread sender_thread(&ServerClient::SendMessage, this);
  sender_thread.detach();

  // Start REPL
  REPLDriver<ServerClient> repl = REPLDriver<ServerClient>(this);
  repl.add_action("reset", "reset", &ServerClient::Reset);
  repl.add_action("users", "users", &ServerClient::Users);
  repl.run();
}

/**
 * Reset database
 *
 */
void ServerClient::Reset(std::string _)
{
  this->cli_driver->print_info("Erasing users!");
  this->db_driver->reset_tables();
}

/**
 * Prints all usernames
 */
void ServerClient::Users(std::string _)
{
  this->cli_driver->print_info("Printing users!");
  std::vector<std::string> usernames = this->db_driver->get_users();
  if (usernames.size() == 0)
  {
    this->cli_driver->print_info("No registered users!");
    return;
  }
  for (std::string username : usernames)
  {
    this->cli_driver->print_info(username);
  }
}

/**
 * @brief Forward responses to each corresponding user
 */
bool ServerClient::SendMessage()
{
  std::shared_ptr<CryptoDriver> crypto_driver =
      std::make_shared<CryptoDriver>();
  try
  {
    while (1)
    {
      std::vector<unsigned char> receivedData;
      bool hasData = msg_q.try_pop(receivedData);
      if (hasData)
      {
        std::cout << "Received message" << std::endl;
        UserToUser_Server_Message receivedMsg;
        receivedMsg.deserialize(receivedData);
        // check if the recipient exists
        if (this->networkMap.find(receivedMsg.recipientID) == this->networkMap.end())
        {
          std::string warning = receivedMsg.recipientID + " is not logged in; fail to send message";
          cli_driver->print_warning(warning);
          SecureNetwork sender = this->networkMap[receivedMsg.senderID];
          receivedMsg.server_warning = warning;
          std::vector<unsigned char> sendVal = crypto_driver->encrypt_and_tag(sender.AES_key, sender.HMAC_key, &receivedMsg);
          sender.network_driver->send(sendVal);
        } else {
          SecureNetwork recipient = this->networkMap[receivedMsg.recipientID];
          receivedMsg.server_warning = "";
          std::vector<unsigned char> sendVal = crypto_driver->encrypt_and_tag(recipient.AES_key, recipient.HMAC_key, &receivedMsg);
          recipient.network_driver->send(sendVal);
        }
      }
    }
    return true;
  }
  catch (...)
  {
    cli_driver->print_warning("server threw an error");
    return false;
  }
}

/**
 * @brief This is the logic for the listener thread
 */
void ServerClient::ListenForConnections(int port)
{
  while (1)
  {
    // Create new network driver and crypto driver for this connection
    std::shared_ptr<NetworkDriver> network_driver =
        std::make_shared<NetworkDriverImpl>();
    std::shared_ptr<CryptoDriver> crypto_driver =
        std::make_shared<CryptoDriver>();
    network_driver->listen(port);
    std::thread connection_thread(&ServerClient::HandleConnection, this,
                                  network_driver, crypto_driver);
    connection_thread.detach();
  }
}

/**
 * Handle keygen and handle either logins or registrations. This function should:
 * 1) Handle key exchange with the user
 * 2) Reads a UserToServer_IDPrompt_Message and determines whether the user is attempting
 * to login or register and calls the corresponding function.
 * 3) Recursively listen for the new messages from this user and push into concurrent queue
 */
bool ServerClient::HandleConnection(
    std::shared_ptr<NetworkDriver> network_driver,
    std::shared_ptr<CryptoDriver> crypto_driver)
{
  try
  {
    std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys = HandleKeyExchange(network_driver, crypto_driver);
    // read message
    std::vector<unsigned char> userData = network_driver->read();
    auto userVal = crypto_driver->decrypt_and_verify(keys.first, keys.second, userData);
    if (!userVal.second)
    {
      network_driver->disconnect();
      throw std::runtime_error("server fails to decrypt user message");
    }
    // register or login
    UserToServer_IDPrompt_Message userMsg;
    userMsg.deserialize(userVal.first);
    if (userMsg.new_user)
    {
      HandleRegister(network_driver, crypto_driver, userMsg.id, keys);
    }
    else
    {
      HandleLogin(network_driver, crypto_driver, userMsg.id, keys);
    }
    this->networkMap[userMsg.id] = SecureNetwork{network_driver, keys.first, keys.second};
    // accept user to user messages
    while (1)
    {
      std::cout << "listening for messages" << std::endl;
      std::vector<unsigned char> newData = network_driver->read();
      auto newVal = crypto_driver->decrypt_and_verify(keys.first, keys.second, newData);
      if (!newVal.second)
      {
        network_driver->disconnect();
        throw std::runtime_error("server fails to decrypt user message");
      }
      msg_q.push(newVal.first);
    }
    return true;
  }
  catch (...)
  {
    cli_driver->print_warning("Connection threw an error");
    network_driver->disconnect();
    return false;
  }
}

/**
 * Diffie-Hellman key exchange. This function should:
 * 1) Receive the user's public value
 * 2) Generate and send a signed DH public value
 * 2) Generate a DH shared key and generate AES and HMAC keys.
 * @return tuple of AES_key, HMAC_key
 */
std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock>
ServerClient::HandleKeyExchange(std::shared_ptr<NetworkDriver> network_driver,
                                std::shared_ptr<CryptoDriver> crypto_driver)
{

  // listen user public value
  UserToServer_DHPublicValue_Message userPubMsg;
  std::vector<unsigned char> userPubVal = network_driver->read();
  userPubMsg.deserialize(userPubVal);

  // Generate public value
  std::tuple<DH, SecByteBlock, SecByteBlock> DH_info = crypto_driver->DH_initialize();

  // Send public value
  ServerToUser_DHPublicValue_Message pubMsg;
  pubMsg.server_public_value = std::get<2>(DH_info);
  pubMsg.user_public_value = userPubMsg.public_value;

  // Sign server + user public values
  std::vector<unsigned char> sign = concat_byteblocks(pubMsg.server_public_value, pubMsg.user_public_value);
  pubMsg.server_signature = crypto_driver->DSA_sign(this->DSA_signing_key, sign);
  std::vector<unsigned char> pubVal;
  pubMsg.serialize(pubVal);
  network_driver->send(pubVal);

  // Generate keys
  SecByteBlock shared_key = crypto_driver->DH_generate_shared_key(std::get<0>(DH_info), std::get<1>(DH_info), userPubMsg.public_value);
  SecByteBlock AES_key = crypto_driver->AES_generate_key(shared_key);
  SecByteBlock HMAC_key = crypto_driver->HMAC_generate_key(shared_key);
  return std::pair<SecByteBlock, SecByteBlock>(AES_key, HMAC_key);
}

std::string ServerClient::SaltAndPassword(
    std::shared_ptr<NetworkDriver> network_driver,
    std::shared_ptr<CryptoDriver> crypto_driver,
    std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys,
    std::string salt)
{
  // send salt
  ServerToUser_Salt_Message saltMsg;
  saltMsg.salt = salt;
  std::vector<unsigned char> saltVal = crypto_driver->encrypt_and_tag(keys.first, keys.second, &saltMsg);
  network_driver->send(saltVal);

  // receive hashed password
  std::vector<unsigned char> pwData = network_driver->read();
  auto pwVal = crypto_driver->decrypt_and_verify(keys.first, keys.second, pwData);
  if (!pwVal.second)
  {
    throw std::runtime_error("server fails to decrypt");
  }
  UserToServer_HashedAndSaltedPassword_Message pwMsg;
  pwMsg.deserialize(pwVal.first);
  return pwMsg.hspw;
}

void ServerClient::Verify2FA(
    std::shared_ptr<NetworkDriver> network_driver,
    std::shared_ptr<CryptoDriver> crypto_driver,
    std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys,
    std::string prg_seed)
{
  // Receive 2FA response
  std::vector<unsigned char> prgData = network_driver->read();
  auto prgVal = crypto_driver->decrypt_and_verify(keys.first, keys.second, prgData);
  if (!prgVal.second)
  {
    throw std::runtime_error("server fails to decrypt");
  }
  UserToServer_PRGValue_Message prgMsg;
  prgMsg.deserialize(prgVal.first);
  // Verify 2FA response
  bool is_valid_prg = false;
  SecByteBlock seed = string_to_byteblock(prg_seed);
  Integer t = crypto_driver->nowish();
  for (int i = 0; i < 60; i++)
  {
    SecByteBlock serverPrg = crypto_driver->prg(seed, integer_to_byteblock(t + i), PRG_SIZE);
    if (serverPrg == prgMsg.value)
    {
      is_valid_prg = true;
      break;
    }
  }
  if (!is_valid_prg)
  {
    throw std::runtime_error("invalid prg value");
  }
}

void ServerClient::SendCertificate(
    std::shared_ptr<NetworkDriver> network_driver,
    std::shared_ptr<CryptoDriver> crypto_driver,
    std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys,
    std::string id)
{

  // receive verification
  std::vector<unsigned char> verifyData = network_driver->read();
  auto verifyVal = crypto_driver->decrypt_and_verify(keys.first, keys.second, verifyData);
  if (!verifyVal.second)
  {
    throw std::runtime_error("server fails to decrypt");
  }
  UserToServer_VerificationKey_Message verifyMsg;
  verifyMsg.deserialize(verifyVal.first);
  // sign certificate
  Certificate_Message certificate;
  certificate.id = id;
  certificate.verification_key = verifyMsg.verification_key;
  std::vector<unsigned char> sign = concat_string_and_dsakey(id, verifyMsg.verification_key);
  certificate.server_signature = crypto_driver->DSA_sign(this->DSA_signing_key, sign);
  // send certificate
  ServerToUser_IssuedCertificate_Message certMsg;
  certMsg.certificate = certificate;
  std::vector<unsigned char> certVal = crypto_driver->encrypt_and_tag(keys.first, keys.second, &certMsg);
  network_driver->send(certVal);
}

/**
 * Log in the given user. This function should:
 * 1) Find the user in the database.
 * 2) Send the user's salt and receive a hash of the salted password.
 * 3) Try all possible peppers until one succeeds.
 * 4) Receive a 2FA response and verify it was generated in the last 60 seconds.
 * 5) Receive the user's verification key, and sign it to create a certificate.
 * @param id id of the user logging in
 * @param keys tuple of AES_key, HMAC_key corresponding to this session
 */
void ServerClient::HandleLogin(
    std::shared_ptr<NetworkDriver> network_driver,
    std::shared_ptr<CryptoDriver> crypto_driver, std::string id,
    std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys)
{

  // get user
  UserRow user = this->db_driver->find_user(id);
  if (user.password_salt == "")
  {
    throw std::runtime_error("the user is not in the database when login");
  }

  std::string hspw = SaltAndPassword(network_driver, crypto_driver, keys, user.password_salt);

  // check for pepper
  bool is_valid_password = false;
  for (int i = 0; i < 256; i++)
  {
    std::string pepper(1, (char)i);
    if (crypto_driver->hash(hspw + pepper) == user.password_hash)
    {
      is_valid_password = true;
      break;
    }
  }
  if (!is_valid_password)
  {
    throw std::runtime_error("invalid password hash when login");
  }

  // 2FA response
  Verify2FA(network_driver, crypto_driver, keys, user.prg_seed);

  // certificate
  SendCertificate(network_driver, crypto_driver, keys, id);
}

/**
 * Register the given user. This function should:
 * 1) Confirm that the user in not the database.
 * 2) Generate and send a salt and receives a hash of the salted password.
 * 3) Generate a pepper and store a second hash of the response + pepper.
 * 4) Generate and sends a PRG seed to the user
 * 4) Receive a 2FA response and verify it was generated in the last 60 seconds.
 * 5) Receive the user's verification key, and sign it to create a certificate.
 * 6) Store the user in the database.
 * @param id id of the user logging in
 * @param keys tuple of AES_key, HMAC_key corresponding to this session
 */
void ServerClient::HandleRegister(
    std::shared_ptr<NetworkDriver> network_driver,
    std::shared_ptr<CryptoDriver> crypto_driver, std::string id,
    std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys)
{

  // Check for user in the database.
  UserRow user = this->db_driver->find_user(id);
  if (user.user_id != "")
  {
    throw std::runtime_error("the user is already in the database");
  }
  user.user_id = id;

  // Generate and send salt
  user.password_salt = byteblock_to_string(crypto_driver->png(SALT_SIZE));
  std::string hspw = SaltAndPassword(network_driver, crypto_driver, keys, user.password_salt);

  // Generate pepper and store the hash
  std::string pepper = byteblock_to_string(crypto_driver->png(PEPPER_SIZE));
  user.password_hash = crypto_driver->hash(hspw + pepper);

  // Generate and send PRG seed
  SecByteBlock seed = crypto_driver->png(PRG_SIZE);
  user.prg_seed = byteblock_to_string(seed);
  ServerToUser_PRGSeed_Message prgMsg;
  prgMsg.seed = seed;
  std::vector<unsigned char> prgVal = crypto_driver->encrypt_and_tag(keys.first, keys.second, &prgMsg);
  network_driver->send(prgVal);

  // 2FA response
  Verify2FA(network_driver, crypto_driver, keys, user.prg_seed);

  // certificate
  SendCertificate(network_driver, crypto_driver, keys, id);

  // Store the user in the database.
  this->db_driver->insert_user(user);
}
