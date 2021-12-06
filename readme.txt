OS: Linux / Oracle VM VirtualBox (Linux OS)
Network setting: Bridged Adapter
Language: C++
Library used: Crypto++® Library 8.5

Compilation
OS: Linux OS (Ubuntu)

Machine 1
--Server--
Open terminal 
Run the following commands:  
sudo apt-get update 
sudo apt-get install libcrypto++-dev libcrypto++-doc libcrypto++-util (Install Crypto++® Library 8.5)
cd Desktop (cpp file location in my case is Desktop)
g++ -g3 -ggdb -O0 -Wall -Wextra -Wno-unused -o Server server.cpp -lcryptopp
./Server

Machine 2
--Client--
Open terminal 
Run the following commands:  
sudo apt-get update 
sudo apt-get install libcrypto++-dev libcrypto++-doc libcrypto++-util (Install Crypto++® Library 8.5)
cd Desktop (cpp file location in my case is Desktop)
g++ -g3 -ggdb -O0 -Wall -Wextra -Wno-unused -o Client client.cpp -lcryptopp
./Client

IP Address used: 192.168.0.61
Port range: 1 - 65535