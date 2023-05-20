[![Open in Visual Studio Code](https://classroom.github.com/assets/open-in-vscode-718a45dd9cf7e7f842a935f5ebbe5719a5e09af4491e668f4dbf3b35d5cca122.svg)](https://classroom.github.com/online_ide?assignment_repo_id=11009676&assignment_repo_type=AssignmentRepo)
# Final Project: Group Chat

## Overview

We assume that the server is semi-honest. We choose to use a central server because it is more efficient and scalable for multi-user communication. 

All the messages between the clients would go through the server as a direct message from a sender to a recipient. We assumed that the server would send the original messages to the correct recipients. Since this message is encrypted using the shared key between the user, the server would not be able to learn the user messages. 

Since the group messages are forwarded to the server as multiple direct messages from a user to other users, the server will not be able to learn the explicit group structure. However, the server may be able to learn the group structure by observing messaging patterns if a few users always message each other at the same time. 

## Demo
![group chat demo](https://github.com/zhang-tianran/Group-Chat/demo.png)

## Specification
### Server

### User

## Running the code
To build the project, `cd` into the `build` folder and run `cmake ..`. This will generate a set of Makefiles building the whole project. From here, you can run `make` to generate a binary (`chat_user` and `chat_server`) you can run, and you can run make check to run any tests you write in the test folder.

### Server
To run the server binary, run `./chat_server <port> <config file>`. We have provided server config files for you to use; you shouldn't need to change them. Afterwards, the server will start listening for connections and handle them in separate threads.

- list registered users: `$ users`
- reset registered users: `$ reset`

### User
To run the user binary, run `./chat_user <config file>`. You may find example users from the `config` folder. 

#### Full Command List
- login and connect: `$ login <address> <port>`
- register and connect: `$ register <address> <port>`
- direct message: `$ dm <userID> <message>`
- create group: `$ create <groupID> <userID> [userID] [userID] ...`
- group message: `$ gm <groupID> <message>`
- add member to group: `$ add <groupID> <userID>`
- remove self from group: `$ rm <groupID>`
- list groups and members: `$ groups`
- disconnect from server: `$ exit`

## Future Development
1. Apply double rachet protocol for key exchange between the users
2. Completely hide the group structure from the server by using
multiple servers or other indeterministic mechanisms
3. Refine user interface

## _Reference_
P. Rösler, C. Mainka and J. Schwenk, "More is Less: On the End-to-End Security of Group Chats in Signal, WhatsApp, and Threema," 2018 IEEE European Symposium on Security and Privacy (EuroS\&P), London, UK, 2018, pp. 415-429, doi: 10.1109/EuroSP.2018.00036.