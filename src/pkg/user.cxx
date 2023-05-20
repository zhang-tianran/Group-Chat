#include <cmath>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>
#include <sys/ioctl.h>
#include <vector>
#include <numeric>
#include <thread>
#include <chrono>

#include <boost/asio.hpp>
#include <boost/lexical_cast.hpp>

#include "../../include-shared/constants.hpp"
#include "../../include-shared/logger.hpp"
#include "../../include-shared/messages.hpp"
#include "../../include-shared/util.hpp"
#include "../../include/drivers/repl_driver.hpp"
#include "../../include/pkg/user.hpp"

/**
 * Constructor. Loads server public key.
 */
UserClient::UserClient(std::shared_ptr<NetworkDriver> network_driver,
                       std::shared_ptr<CryptoDriver> crypto_driver,
                       UserConfig user_config)
{

  // Make shared variables.
  this->cli_driver = std::make_shared<CLIDriver>();
  this->crypto_driver = crypto_driver;
  this->network_driver = network_driver;
  this->user_config = user_config;

  this->cli_driver->init();

  // Load server's key
  try
  {
    LoadDSAPublicKey(user_config.server_verification_key_path,
                     this->DSA_server_verification_key);
  }
  catch (CryptoPP::FileStore::OpenErr)
  {
    this->cli_driver->print_warning("Error loading server keys; exiting");
    throw std::runtime_error("Client could not open server's keys.");
  }

  // Load keys
  try
  {
    LoadDSAPrivateKey(this->user_config.user_signing_key_path,
                      this->DSA_signing_key);
    LoadDSAPublicKey(this->user_config.user_verification_key_path,
                     this->DSA_verification_key);
    LoadCertificate(this->user_config.user_certificate_path, this->certificate);
    this->DSA_verification_key = this->certificate.verification_key;
    LoadPRGSeed(this->user_config.user_prg_seed_path, this->prg_seed);
  }
  catch (CryptoPP::FileStore::OpenErr)
  {
    this->cli_driver->print_warning("Error loading keys, you may consider "
                                    "registering or logging in again!");
  }
  catch (std::runtime_error &_)
  {
    this->cli_driver->print_warning("Error loading keys, you may consider "
                                    "registering or logging in again!");
  }
}

/**
 * Starts repl.
 */
void UserClient::run()
{
  REPLDriver<UserClient> repl = REPLDriver<UserClient>(this);
  repl.add_action("login", "login <address> <port>",
                  &UserClient::HandleLoginOrRegister);
  repl.add_action("register", "register <address> <port>",
                  &UserClient::HandleLoginOrRegister);
  repl.run();
}

/**
 * Diffie-Hellman key exchange with server
 * 1) Generate a keypair, a, g^a and send it to the server.
 * 2) Receive a public value (g^a, g^b) from the server and verify its
 * signature. 3) Verify that the public value the server received is g^a. 4)
 * Generate a DH shared key and generate AES and HMAC keys.
 * @return tuple of AES_key, HMAC_key
 */
std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock>
UserClient::HandleServerKeyExchange()
{

  // Generate key pair and send public key to server.
  std::tuple<DH, SecByteBlock, SecByteBlock> DH_info = this->crypto_driver->DH_initialize();
  UserToServer_DHPublicValue_Message pubMsg;
  pubMsg.public_value = std::get<2>(DH_info);
  std::vector<unsigned char> pubVal;
  pubMsg.serialize(pubVal);
  network_driver->send(pubVal);

  // Receive public value from the server
  ServerToUser_DHPublicValue_Message serverPubMsg;
  std::vector<unsigned char> serverPubVal = this->network_driver->read();
  serverPubMsg.deserialize(serverPubVal);

  // Verify signiture
  std::vector<unsigned char> serverMsg = concat_byteblocks(serverPubMsg.server_public_value, serverPubMsg.user_public_value);
  bool signiture = this->crypto_driver->DSA_verify(this->DSA_server_verification_key, serverMsg, serverPubMsg.server_signature);
  if (!signiture)
  {
    this->network_driver->disconnect();
    throw std::runtime_error("invalid server signiture");
  }

  // Verify user public value
  if (serverPubMsg.user_public_value != pubMsg.public_value)
  {
    this->network_driver->disconnect();
    throw std::runtime_error("invalid user public value from server");
  }

  // Generate DH shared key, AES and HMAC keys.
  SecByteBlock shared_key = this->crypto_driver->DH_generate_shared_key(std::get<0>(DH_info), std::get<1>(DH_info), serverPubMsg.server_public_value);
  SecByteBlock AES_key = this->crypto_driver->AES_generate_key(shared_key);
  SecByteBlock HMAC_key = this->crypto_driver->HMAC_generate_key(shared_key);
  return std::pair<SecByteBlock, SecByteBlock>(AES_key, HMAC_key);
}

/**
 * User login or register; connect to server
 */
void UserClient::HandleLoginOrRegister(std::string input)
{
  std::vector<std::string> input_split = string_split(input, ' ');
  if (input_split.size() != 3)
  {
    this->cli_driver->print_left("invalid number of arguments.");
    return;
  }
  // Connect to server
  std::string address = input_split[1];
  int port = std::stoi(input_split[2]);
  this->network_driver->connect(address, port);

  // key exchange
  std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys = HandleServerKeyExchange();

  // login or register
  this->DoLoginOrRegister(keys, input_split[0]);

  // clean screen
  this->cli_driver->init();
  this->cli_driver->print_success("Connected!");

  // Set up communication
  boost::thread msgListener = boost::thread(boost::bind(&UserClient::ReceiveThread, this, keys));
  this->SendThread(keys);
  msgListener.join();
}

/**
 * User login or register. This function should:
 * 1) Tells the server our ID and intent.
 * 2) Receives a salt from the server.
 * 3) Generates and sends a hashed and salted password.
 * 4) (if registering) Receives a PRG seed from the server.
 * 5) Generates and sends a 2FA response.
 * 6) Generates a DSA keypair, and send vk to the server for signing.
 * 7) Receives and save cert in this->certificate
 * 8) Receives and saves the keys, certificate, and prg seed.
 */
void UserClient::DoLoginOrRegister(std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys,
                                   std::string input)
{

  // send id and intent
  UserToServer_IDPrompt_Message idMsg;
  idMsg.id = this->user_config.user_username;
  idMsg.new_user = (input == "register") ? true : false;
  std::vector<unsigned char> idVal = this->crypto_driver->encrypt_and_tag(keys.first, keys.second, &idMsg);
  network_driver->send(idVal);

  // Receive salt from the server
  std::vector<unsigned char> saltData = this->network_driver->read();
  auto saltVal = crypto_driver->decrypt_and_verify(keys.first, keys.second, saltData);
  if (!saltVal.second)
  {
    this->network_driver->disconnect();
    throw std::runtime_error("user fails to decrypt");
  }
  ServerToUser_Salt_Message saltMsg;
  saltMsg.deserialize(saltVal.first);

  // send hashed password + salt
  UserToServer_HashedAndSaltedPassword_Message pwMsg;
  pwMsg.hspw = this->crypto_driver->hash(this->user_config.user_password + saltMsg.salt);
  std::vector<unsigned char> pwVal = this->crypto_driver->encrypt_and_tag(keys.first, keys.second, &pwMsg);
  this->network_driver->send(pwVal);

  // register -> receive PRG seed
  if (input == "register")
  {
    std::vector<unsigned char> prgData = this->network_driver->read();
    auto prgVal = crypto_driver->decrypt_and_verify(keys.first, keys.second, prgData);
    if (!prgVal.second)
    {
      this->network_driver->disconnect();
      throw std::runtime_error("user fails to decrypt");
    }
    ServerToUser_PRGSeed_Message prgMsg;
    prgMsg.deserialize(prgVal.first);
    this->prg_seed = prgMsg.seed;
  }

  // generate and send 2FA response
  SecByteBlock t = integer_to_byteblock(this->crypto_driver->nowish());
  SecByteBlock userPrg = this->crypto_driver->prg(this->prg_seed, t, PRG_SIZE);
  UserToServer_PRGValue_Message userPrgMsg;
  userPrgMsg.value = userPrg;
  std::vector<unsigned char> userPrgVal = this->crypto_driver->encrypt_and_tag(keys.first, keys.second, &userPrgMsg);
  this->network_driver->send(userPrgVal);

  // Generates DSA keypair and send vk to the server
  std::pair<DSA::PrivateKey, DSA::PublicKey> DSA_keys = this->crypto_driver->DSA_generate_keys();
  this->DSA_signing_key = DSA_keys.first;
  UserToServer_VerificationKey_Message userVkMsg;
  userVkMsg.verification_key = DSA_keys.second;
  std::vector<unsigned char> userVkVal = this->crypto_driver->encrypt_and_tag(keys.first, keys.second, &userVkMsg);
  this->network_driver->send(userVkVal);

  // receive and save cert
  std::vector<unsigned char> certData = network_driver->read();
  auto certVal = crypto_driver->decrypt_and_verify(keys.first, keys.second, certData);
  if (!certVal.second)
  {
    this->network_driver->disconnect();
    throw std::runtime_error("user fails to decrypt");
  }
  ServerToUser_IssuedCertificate_Message certMsg;
  certMsg.deserialize(certVal.first);
  this->DSA_verification_key = certMsg.certificate.verification_key;
  this->certificate = certMsg.certificate;

  // save user config
  SaveDSAPrivateKey(user_config.user_signing_key_path, this->DSA_signing_key);
  SaveDSAPublicKey(user_config.user_verification_key_path, this->DSA_verification_key);
  SaveCertificate(user_config.user_certificate_path, this->certificate);
  SavePRGSeed(user_config.user_prg_seed_path, this->prg_seed);
}

/**
 * Diffie-Hellman key exchange with another user.
 * This function should generate a keypair, a, g^a,
 * signs it, and sends it to the other user.
 * Return true if successed and false if the recipient does not exist
 */
void UserClient::SendUserKeyExchange(std::string recipientID, std::pair<SecByteBlock, SecByteBlock> keys)
{
  // Generate keypair
  std::tuple<DH, SecByteBlock, SecByteBlock> DH_info = this->crypto_driver->DH_initialize();
  this->myDHinfo[recipientID] = DH_info;

  UserToUser_DHPublicValue_Message pubMsg;
  pubMsg.public_value = std::get<2>(DH_info);
  pubMsg.certificate = this->certificate;
  // sign
  std::vector<unsigned char> sign = concat_byteblock_and_cert(pubMsg.public_value, this->certificate);
  pubMsg.user_signature = this->crypto_driver->DSA_sign(this->DSA_signing_key, sign);
  // send
  std::vector<unsigned char> pubValData;
  pubMsg.serialize(pubValData);
  SendMsg(keys, pubValData, MessageType::Action::KeyExchange, recipientID);
}

/**
 * Diffie-Hellman key exchange with another user. This function shuold:
 * 1) Receive a public value from the other user and verifies its signature and
 * certificate
 * 2) Send over public value, if not already
 * 3) Generate a DH shared key and generate AES and HMAC keys.
 * 4) Store the other user's AES and HMAC keys and DSA verification key in map
 */
void UserClient::ReceiveUserKeyExchange(std::vector<unsigned char> otherPubVal, std::pair<SecByteBlock, SecByteBlock> keys)
{
  // Receive public value from the other user
  UserToUser_DHPublicValue_Message otherPubMsg;
  otherPubMsg.deserialize(otherPubVal);

  // verify signature and certificate
  std::vector<unsigned char> userSigniture = concat_byteblock_and_cert(otherPubMsg.public_value, otherPubMsg.certificate);
  bool userSign = this->crypto_driver->DSA_verify(otherPubMsg.certificate.verification_key, userSigniture, otherPubMsg.user_signature);
  if (!userSign)
  {
    this->network_driver->disconnect();
    throw std::runtime_error("invalid DSA user signiture for verification key");
  }

  // verify server signiture
  std::vector<unsigned char> serverSigniture = concat_string_and_dsakey(otherPubMsg.certificate.id, otherPubMsg.certificate.verification_key);
  bool serverSign = this->crypto_driver->DSA_verify(this->DSA_server_verification_key, serverSigniture, otherPubMsg.certificate.server_signature);
  if (!serverSign)
  {
    this->network_driver->disconnect();
    throw std::runtime_error("invalid DSA server signiture for verification key");
  }

  // send over DH info
  if (this->myDHinfo.find(otherPubMsg.certificate.id) == this->myDHinfo.end())
  {
    SendUserKeyExchange(otherPubMsg.certificate.id, keys);
  }

  std::tuple<DH, SecByteBlock, SecByteBlock> DH_info = myDHinfo[otherPubMsg.certificate.id];

  // Generate DH shared key, AES and HMAC keys.
  SecByteBlock shared_key = this->crypto_driver->DH_generate_shared_key(std::get<0>(DH_info), std::get<1>(DH_info), otherPubMsg.public_value);
  SecByteBlock AES_key = this->crypto_driver->AES_generate_key(shared_key);
  SecByteBlock HMAC_key = this->crypto_driver->HMAC_generate_key(shared_key);

  this->keyMap[otherPubMsg.certificate.id] = UserKeys{otherPubMsg.certificate.verification_key, AES_key, HMAC_key};
}

/**
 * Wait for response public value from the other user.
 */
bool UserClient::DoKeyExchange(std::string userID, std::pair<SecByteBlock, SecByteBlock> keys){
  SendUserKeyExchange(userID, keys);
  // wait for other public value
  for (int i = 0; i < 3; i++) {
    if (this->keyMap.find(userID) != this->keyMap.end())
    {
      return true;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
  } 
  // fail to receive other user's value
  return false;
}

/**
 * This function will handle different messages received from the server
 */
void UserClient::HandleReceiveMessage(std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys,
                                      std::vector<unsigned char> serverData)
{

  // Verify data from the server
  auto serverVal = crypto_driver->decrypt_and_verify(keys.first, keys.second, serverData);
  if (!serverVal.second)
  {
    this->network_driver->disconnect();
    throw std::runtime_error("user received invalid server MAC");
  }
  UserToUser_Server_Message serverMsg;
  serverMsg.deserialize(serverVal.first);

  // check server warning
  if(serverMsg.server_warning != "") {
    this->cli_driver->print_warning(serverMsg.server_warning);
    return;
  }

  // check if key exchange required
  if (this->keyMap.find(serverMsg.senderID) == this->keyMap.end())
  {
    UserToUser_General_Message generalMsg;
    generalMsg.deserialize(serverMsg.userData);

    if (generalMsg.action == MessageType::Action::KeyExchange)
    {
      ReceiveUserKeyExchange(generalMsg.userData, keys);
      return;
    }
    else
    {
      this->cli_driver->print_warning("Error: " + serverMsg.senderID + "is not your friend");
      return;
    }
  }

  // Verify data from other user
  UserKeys ukeys = this->keyMap[serverMsg.senderID];
  auto userVal = crypto_driver->decrypt_and_verify(ukeys.AES_key, ukeys.HMAC_key, serverMsg.userData);
  if (!userVal.second)
  {
    this->network_driver->disconnect();
    throw std::runtime_error("user received invalid user MAC");
  }

  UserToUser_General_Message userMsg;
  userMsg.deserialize(userVal.first);

  switch (userMsg.action)
  {
    case MessageType::Action::Message:
    {
      UserToUser_Message_Message typeMsg;
      typeMsg.deserialize(userMsg.userData);
      if (typeMsg.groupID == "")
      {
        // individual message
        cli_driver->print_left(serverMsg.senderID + ": " + typeMsg.msg);
      }
      else
      {
        // group message
        if (this->groupMap.find(typeMsg.groupID) == this->groupMap.end())
        {
          cli_driver->print_warning("received message from an unknown group");
        }
        cli_driver->print_left(typeMsg.groupID + " " + serverMsg.senderID + ": " + typeMsg.msg);
      }
      break;
    }
    case MessageType::Action::GroupChange:
    {
      UserToUser_GroupChange_Message typeMsg;
      typeMsg.deserialize(userMsg.userData);
      if (typeMsg.is_leaving)
      {
        groupMap[typeMsg.groupID].erase(typeMsg.userID);
        cli_driver->print_info("User " + typeMsg.userID + " has left the group " + typeMsg.groupID);
      }
      else
      {
        // add friend
        if (this->keyMap.find(typeMsg.userID) == this->keyMap.end())
        {
          if (!DoKeyExchange(typeMsg.userID, keys)) {
            return;
          };
        }
        groupMap[typeMsg.groupID].insert(typeMsg.userID);
        cli_driver->print_info("User " + serverMsg.senderID + " has added" + typeMsg.userID + "the group " + typeMsg.groupID);
      }
      // print info
      std::string members = "";
      for (std::string userID : groupMap[typeMsg.groupID])
      {
        members += userID + " ";
      }
      cli_driver->print_info("Current members of the group " + typeMsg.groupID + " are: " + members);
      break;
    }
    case MessageType::Action::CreateGroup:
    {
      UserToUser_CreateGroup_Message typeMsg;
      typeMsg.deserialize(userMsg.userData);
      // print group members
      std::set<std::string> groupMembers;
      groupMembers = typeMsg.members;
      groupMembers.insert(serverMsg.senderID);
      groupMembers.erase(serverMsg.recipientID);
      std::string members = "";
      for (std::string userID : groupMembers)
      {
        // add friend
        if (this->keyMap.find(userID) == this->keyMap.end())
        {
          DoKeyExchange(userID, keys);
        }
        members += userID + " ";
      }
      cli_driver->print_info("Group " + typeMsg.groupID + " has been created by " + serverMsg.senderID + " with members: " + members);
      this->groupMap[typeMsg.groupID] = groupMembers;
      break;
    }
    default:
      cli_driver->print_warning("received unknown message type");
      break;
    };
}

/**
 * Listen for messages and print to CLI.
 */
void UserClient::ReceiveThread(
    std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys)
{
  while (true)
  {
    std::vector<unsigned char> encrypted_msg_data;
    try
    {
      encrypted_msg_data = this->network_driver->read();
    }
    catch (std::runtime_error &_)
    {
      this->cli_driver->print_info("Server is closed, end connection");
      return;
    }
    HandleReceiveMessage(keys, encrypted_msg_data);
  }
}

/**
 * Encrypt the message using user key and server key, and send the message. 
 */
void UserClient::SendMsg(std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys,
                         std::vector<unsigned char> userData,
                         MessageType::Action action,
                         std::string recipient)
{
  // set general data
  UserToUser_General_Message generalMsg;
  generalMsg.action = action;
  generalMsg.userData = userData;

  std::vector<unsigned char> serverData;
  if (action == MessageType::Action::KeyExchange)
  {
    generalMsg.serialize(serverData);
  }
  else
  {
    // encrypt using user key
    UserKeys ukeys = this->keyMap[recipient];
    serverData = this->crypto_driver->encrypt_and_tag(ukeys.AES_key, ukeys.HMAC_key, &generalMsg);
  }

  // encrypt using server key
  UserToUser_Server_Message serverMsg;
  serverMsg.senderID = this->user_config.user_username;
  serverMsg.recipientID = recipient;
  serverMsg.userData = serverData;
  serverMsg.server_warning = "";

  std::vector<unsigned char> msg_data = this->crypto_driver->encrypt_and_tag(keys.first, keys.second, &serverMsg);
  try
  {
    this->network_driver->send(msg_data);
  }
  catch (std::runtime_error &_)
  {
    this->cli_driver->print_info("Server is closed, end connection");
    this->network_driver->disconnect();
    return;
  }
}

/**
 * Prepare and send group change message.
 */
void UserClient::GroupChange(std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys,
                             std::string groupID, std::string userID, bool is_leaving)
{
  for (std::string user : this->groupMap[groupID])
  {
    // only send to friends
    if (this->keyMap.find(user) != this->keyMap.end())
    {
      UserToUser_GroupChange_Message typeMsg;
      typeMsg.userID = userID;
      typeMsg.groupID = groupID;
      typeMsg.is_leaving = is_leaving;
      std::vector<unsigned char> userData;
      typeMsg.serialize(userData);
      SendMsg(keys, userData, MessageType::Action::GroupChange, user);
    }
  }
}

/**
 * Listen for stdin and send to other party.
 */
void UserClient::SendThread(
    std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys)
{
  std::string input;
  while (std::getline(std::cin, input))
  {
    // Read from STDIN.
    if (input != "")
    {
      std::vector<std::string> args = string_split(input, ' ');
      if (args[0] == "create")
      {
        if (args.size() < 3)
        {
          this->cli_driver->print_left("invalid number of arguments.");
          continue;
        }
        std::set<std::string> groupMembers;
        for (int i = 2; i < args.size(); i++)
        {
          // add friend
          if (this->keyMap.find(args[i]) == this->keyMap.end())
          {
            if (!DoKeyExchange(args[i], keys)) {
              continue;
            };
          }
          groupMembers.insert(args[i]);
        }
        this->groupMap[args[1]] = groupMembers;
        for (std::string user : this->groupMap[args[1]])
        {
          UserToUser_CreateGroup_Message typeMsg;
          typeMsg.groupID = args[1];
          typeMsg.members = groupMembers;
          std::vector<unsigned char> userData;
          typeMsg.serialize(userData);
          SendMsg(keys, userData, MessageType::Action::CreateGroup, user);
        }
        cli_driver->print_info("Success!");
      }
      else if (args[0] == "dm")
      {
        if (args.size() < 2)
        {
          this->cli_driver->print_warning("invalid number of arguments.");
          continue;
        }
        std::string userID = args[1];
        // add friend
        if (this->keyMap.find(userID) == this->keyMap.end())
        {
          if (!DoKeyExchange(userID, keys)) {
            continue;
          }
        }
        UserToUser_Message_Message typeMsg;
        typeMsg.groupID = "";
        typeMsg.msg = std::accumulate(std::begin(args) + 3, std::end(args), args[2],
                                      [](std::string s0, std::string const &s1)
                                      { return s0 += " " + s1; });
        std::vector<unsigned char> userData;
        typeMsg.serialize(userData);
        std::string info = "Messaging " + userID + ": " + typeMsg.msg;
        cli_driver->print_right(info);
        SendMsg(keys, userData, MessageType::Action::Message, userID);
      }
      else if (args[0] == "gm")
      {
        if (args.size() < 3)
        {
          this->cli_driver->print_left("invalid number of arguments.");
          continue;
        }
        if (this->groupMap.find(args[1]) == this->groupMap.end())
        {
          this->cli_driver->print_warning("Invalid group name");
          continue;
        }
        for (std::string user : this->groupMap[args[1]])
        {
          UserToUser_Message_Message typeMsg;
          typeMsg.groupID = args[1];
          typeMsg.msg = std::accumulate(std::begin(args) + 3, std::end(args), args[2],
                                        [](std::string s0, std::string const &s1)
                                        { return s0 += " " + s1; });
          std::vector<unsigned char> userData;
          typeMsg.serialize(userData);
                  std::string info = "Messaging " + typeMsg.groupID + ": " + typeMsg.msg;
          cli_driver->print_right(info);
          SendMsg(keys, userData, MessageType::Action::Message, user);
        }
      }
      else if (args[0] == "remove")
      {
        if (args.size() != 2)
        {
          this->cli_driver->print_left("invalid number of arguments.");
          continue;
        }
        if (this->groupMap.find(args[1]) == this->groupMap.end())
        {
          this->cli_driver->print_warning("Invalid group name");
          continue;
        }
        GroupChange(keys, args[1], this->user_config.user_username, true);
        this->groupMap.erase(args[1]);
        cli_driver->print_info("Success!");
      }
      else if (args[0] == "add")
      {
        if (args.size() != 3)
        {
          this->cli_driver->print_left("invalid number of arguments.");
          continue;
        }
        std::string groupID = args[1];
        std::string userID = args[2];
        if (this->groupMap.find(groupID) == this->groupMap.end())
        {
          this->cli_driver->print_warning("Invalid group name");
          continue;
        }
        // add new person
        this->groupMap[groupID].insert(userID);
        if (this->keyMap.find(userID) == this->keyMap.end())
        {
          if (!DoKeyExchange(userID, keys)) {
            continue;
          }
        }
        UserToUser_CreateGroup_Message typeMsg;
        typeMsg.groupID = groupID;
        typeMsg.members = this->groupMap[groupID];
        std::vector<unsigned char> userData;
        typeMsg.serialize(userData);
        SendMsg(keys, userData, MessageType::Action::CreateGroup, userID);
        GroupChange(keys, groupID, userID, false);
        cli_driver->print_info("Success!");
      }
      else if (args[0] == "exit")
      {
        this->cli_driver->print_info("Received EOF; closing connection");
        this->network_driver->disconnect();
        return;
      }
      else if (args[0] == "groups")
      {
        this->cli_driver->print_info("Groups:");
        for (auto const &x : this->groupMap)
        {
          std::string groupName = x.first;
          std::set<std::string> groupMembers = x.second;
          std::string groupMembersString = "";
          for (auto const &y : groupMembers)
          {
            groupMembersString += y + " ";
          }
          this->cli_driver->print_info(groupName + ": " + groupMembersString);
        }
      }
    }
  }
  this->cli_driver->print_info("Received EOF from server; closing connection");
  this->network_driver->disconnect();
}