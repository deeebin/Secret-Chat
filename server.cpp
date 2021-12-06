#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#define _CRT_SECURE_NO_WARNINGS

#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include <iostream>
#include <fstream>

//Crytopp Library
#include <cryptopp/idea.h>
#include <cryptopp/sha.h>
#include <cryptopp/rsa.h>
#include <cryptopp/hex.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/base64.h>

using namespace std;
using namespace CryptoPP;
using CryptoPP::Base64Encoder;
using CryptoPP::Base64Decoder;

string IDEAkey;
string SessionKeyHashValue;

void CFB_IDEA_Decryption(int socket, string keys);
string CFB_IDEA_Encryption(string IDEAkey, int sock);

int socket()
{
	int PORT;
	do {
		cout << "Enter port number to start the listener : ";
		cin >> PORT;
		if (PORT > 65535 || PORT < 1)
		{
			cout << "Please try again. The port range is 1 - 65535." << endl;
		}
	} while (PORT > 65535 || PORT < 1);
	printf("[Server] Successfully listening to port %d\n", PORT);
	cout << "[Server] Waiting for client to connect..." << endl;
	int server_fd, new_socket, valread;
	struct sockaddr_in address;
	int opt = 1;
	int addrlen = sizeof(address);
	// Creating socket file descriptor
	if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
	{
		perror("socket failed");
		exit(EXIT_FAILURE);
	}

	// Forcefully attaching socket
	if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,
		&opt, sizeof(opt)))
	{
		perror("setsockopt");
		exit(EXIT_FAILURE);
	}
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = INADDR_ANY;
	address.sin_port = htons(PORT);

	// Forcefully attaching socket
	if (bind(server_fd, (struct sockaddr*)&address,
		sizeof(address)) < 0)
	{
		perror("bind failed");
		exit(EXIT_FAILURE);
	}
	if (listen(server_fd, 3) < 0)
	{
		perror("listen");
		exit(EXIT_FAILURE);
	}
	if ((new_socket = accept(server_fd, (struct sockaddr*)&address,
		(socklen_t*)&addrlen)) < 0)
	{
		perror("accept");
		exit(EXIT_FAILURE);
	}
	return new_socket;
}

string send_recv(int new_socket, string message, string comments)
{
	int valread;
	char buffer[1024] = { 0 };
	valread = read(new_socket, buffer, 1024);
	cout << "[Server] Receiving/Waiting Message from Client..." << endl;
	cout << "[Message from Client] : " << buffer << endl;
	send(new_socket, message.c_str(), strlen(message.c_str()) + 1, 0);
	cout << "[Details] " << comments << endl << endl;
	return buffer;
}

void verify(string a, string b)
{
	int result = strcmp(a.c_str(), b.c_str());
	cout << "[Server] Verifying the Public Key..." << endl << endl;
	if (result == 0)
	{
		cout << "[Server] Public Key is Matched!" << endl << endl;
	}
	else
	{
		cout << "[Server] Public key is Not Match!" << endl << endl;
		exit(0);
	}
}

string SHA1string(string sha1)
{
	byte digest[SHA1::DIGESTSIZE];
	string message = sha1;
	SHA1 hash;
	hash.CalculateDigest(digest, (const byte*)message.c_str(), message.length());
	HexEncoder encoder;
	string output;
	encoder.Attach(new StringSink(output));
	encoder.Put(digest, sizeof(digest));
	encoder.MessageEnd();
	return output;
}

void sendpacket(int new_socket, string message)
{
	send(new_socket, message.c_str(), strlen(message.c_str()) + 1, 0);
}

string generateSessionKey(int sock, string publickey)
{
	AutoSeededRandomPool prng;
	InvertibleRSAFunction parameters;
	RSA::PublicKey publicKey(parameters);
	parameters.GenerateRandomWithKeySize(prng, 1024);
	SecByteBlock key(IDEA::DEFAULT_KEYLENGTH);
	prng.GenerateBlock(key, key.size());

	//Convert key from bytes to string
	string stringKey, temporary;
	ArraySource(key, sizeof(key), true, new StringSink(stringKey));
	string encodestringKey;
	StringSource encodekey(stringKey, true, new HexEncoder(
		new StringSink(temporary)));
	encodestringKey = temporary.substr(0, 32);
	cout << "[Server] Generating Session Key...\n\n";
	cout << "[Server] Session Key : " << encodestringKey << endl << endl;

	IDEAkey = encodestringKey;
	SessionKeyHashValue = encodestringKey;

	string decodedpubkey;
	StringSource decodekey(publickey, true, new HexDecoder(new StringSink(decodedpubkey)));
	StringSource pubKeySS(decodedpubkey, true);
	publicKey.Load(pubKeySS);

	string encryptedSessionKey;
	RSAES_OAEP_SHA_Encryptor e(publicKey);
	StringSource encryptboth(encodestringKey, true, new PK_EncryptorFilter(prng, e, (new HexEncoder(new StringSink(encryptedSessionKey)))));

	cout << "[Server] Encrypting Session Key with Public Key...\n\n";
	cout << "[Server] Encrypted Session Key : " << encryptedSessionKey << endl << endl;

	return encryptedSessionKey;
}

string CFB_IDEA_Encryption(string IDEAkey, int sock)
{
	AutoSeededRandomPool prng;
	string decodedkey;
	StringSource s(IDEAkey, true, (new HexDecoder(
		new StringSink(decodedkey))
		) // StreamTransformationFilter
	); // StringSource

	SecByteBlock key((const byte*)decodedkey.data(), decodedkey.size());
	const byte iv[] = { 0x12,0x34,0x56,0x78,0x90,0xab,0xcd,0xef };

	string plain;
	string cipher, encoded, recovered;

	/*********************************\
	\*********************************/

	do {
		cout << "Enter Message to Client : ";
		getline(cin, plain);
		if (plain.size() > 1024)
		{
			cout << "[Server] Message Length is Exceed" << endl << endl;
		}
	} while (plain.size() > 1024);
	try
	{
		CFB_Mode< IDEA >::Encryption e;
		e.SetKeyWithIV(key, key.size(), iv);

		StringSource ss1(plain, true,
			new StreamTransformationFilter(e,
				new StringSink(cipher)
			) // StreamTransformationFilter
		); // StringSource
	}
	catch (const Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

	StringSource ss2(cipher, true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	cout << "Cipher Text Entered [HEX Encoded] : " << encoded << endl;
	sendpacket(sock, encoded);
	cout << "[Details] Message is Sent to Client " << endl << endl;
	return plain;
}

void CFB_IDEA_Decryption(int socket, string keys)
{
	int valread;
	char buffer[1024] = { 0 };
	valread = read(socket, buffer, 1024);
	cout << "Cipher Text from Client [HEX Encoded] : " << buffer << endl;
	AutoSeededRandomPool prng;
	string rawcipher, decodedkey;
	StringSource ss2(buffer, true,
		new HexDecoder(
			new StringSink(rawcipher)
		)  //HexEncoder
	); // StringSource

	StringSource s(keys, true, (new HexDecoder(
		new StringSink(decodedkey))));
	SecByteBlock key((const byte*)decodedkey.data(), decodedkey.size());
	const byte iv[] = { 0x12,0x34,0x56,0x78,0x90,0xab,0xcd,0xef };

	try
	{
		CFB_Mode< IDEA >::Decryption d;
		d.SetKeyWithIV(key, key.size(), iv);
		string recovered;

		StringSource ss3(rawcipher, true,
			new StreamTransformationFilter(d,
				new StringSink(recovered)
			) // StreamTransformationFilter
		); // StringSource
		if (recovered == "quit")
		{
			cout << "Program Quit..." << endl << endl;
			sendpacket(socket, buffer);
			exit(1);
		}
		cout << "Decrypted Text : " << recovered << endl << endl;
	}
	catch (const Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}
}

void CFB_IDEA_msgDecrpytionEncryption(int new_socket)
{
	CFB_IDEA_Decryption(new_socket, IDEAkey);
	CFB_IDEA_Encryption(IDEAkey, new_socket);
}

int main(int argc, char const* argv[])
{
	string RecieveMsg = "Server Received.";
	string returnSessionKey;

	int new_socket = socket(), valread;
	cout << "[Server] Client is Connected!" << endl << endl;

	string publickey = send_recv(new_socket, RecieveMsg, "Public Key from Client");

	string hashvalue = send_recv(new_socket, RecieveMsg, "Public Key Hash Value from Client");

	verify(hashvalue, SHA1string(publickey));

	returnSessionKey = generateSessionKey(new_socket, publickey);

	send_recv(new_socket, returnSessionKey, "Server --> Client | Encrypted Session Key is Sent to Client");

	string SHA1SessionEncode = SHA1string(SessionKeyHashValue);

	cout << "[Server] Generating Hash Value Of Encrypted Session Key...\n\n";
	cout << "[Server] SHA-1 Hash of Session Key : " << SHA1SessionEncode << endl << endl;
	returnSessionKey = send_recv(new_socket, SHA1SessionEncode, "Server --> Client | SHA-1 Hash Value of Session Key is Sent to Client");
	
	cout << "IDEA Key : " << IDEAkey << endl << endl;
	bool loop = true;
	cin.ignore();
	do {
		cout << "[Server] Receiving/Waiting Message from Client..." << endl;
		CFB_IDEA_msgDecrpytionEncryption(new_socket);
	} while (loop == true);
	return 0;
}
