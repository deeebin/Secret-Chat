#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#define _CRT_SECURE_NO_WARNINGS

#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <fstream>

//Crytopp Library
#include <cryptopp/cryptlib.h>
#include <cryptopp/rsa.h>
#include <cryptopp/idea.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/des.h>
#include <cryptopp/base64.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>

using namespace std;
using namespace CryptoPP;

string encodedSessionKey, hashEncodedSession, encryptedmsg;

void Save(const string& filename, const BufferedTransformation& bt);
void SaveHex(const string& filename, const BufferedTransformation& bt);
void SaveHexPrivateKey(const string& filename, const PrivateKey& key);
void SaveHexPublicKey(const string& filename, const PublicKey& key);
void sendpacket(int new_socket, string message);

int socket()
{
	cout << "Enter the Server IP Address : ";
	string ip;
	cin >> ip;
	int PORT;
	do {
		cout << "Enter the Port Number : ";
		cin >> PORT;
		if (PORT > 65535 || PORT < 1)
		{
			cout << "Please try again. The port range is 1 - 65535." << endl;
		}
	} while (PORT > 65535 || PORT < 1);
	int sock = 0, valread;
	struct sockaddr_in serv_addr;
	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		printf("\n Socket creation error \n");
		exit(0);
		return -1;
	}

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(PORT);

	// Convert IPv4 and IPv6 addresses from text to binary form
	if (inet_pton(AF_INET, ip.c_str(), &serv_addr.sin_addr) <= 0)
	{
		printf("\nInvalid address/Address not supported \n");
		exit(0);
		return -1;
	}

	if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0)
	{
		printf("\nConnection Failed \n");
		exit(0);
		return -1;
	}
	return sock;
}

void verify(string a, string b)
{
	int result = strcmp(a.c_str(), b.c_str());
	cout << "[Client] Verifying the Session Key..." << endl << endl;
	if (result == 0)
	{
		cout << "[Client] Session Key is Matched!" << endl << endl;
	}
	else
	{
		cout << "[Client] Session Key is Not Matched!" << endl << endl;
		exit(0);
	}
}

void keyGen()
{
	AutoSeededRandomPool rng;
	InvertibleRSAFunction privkey;
	privkey.Initialize(rng, 1024);

	// Generate Private Key
	RSA::PrivateKey privateKey;
	privateKey.GenerateRandomWithKeySize(rng, 1024);
	// Generate Public Key
	RSA::PublicKey publicKey;
	publicKey.AssignFrom(privateKey);
	SaveHexPublicKey("PublicKey.txt", publicKey);
	SaveHexPrivateKey("PrivateKey.txt", privateKey);
}

void Save(const string& filename, const BufferedTransformation& bt)
{
	FileSink file(filename.c_str());
	bt.CopyTo(file);
	file.MessageEnd();
}

void SaveHex(const string& filename, const BufferedTransformation& bt)
{
	HexEncoder encoder;
	bt.CopyTo(encoder);
	encoder.MessageEnd();
	Save(filename, encoder);
}

void SaveHexPrivateKey(const string& filename, const PrivateKey& key)
{
	ByteQueue queue;
	key.Save(queue);
	SaveHex(filename, queue);
}

void SaveHexPublicKey(const string& filename, const PublicKey& key)
{
	ByteQueue queue;
	key.Save(queue);
	SaveHex(filename, queue);
}

string grabfilecontent(string filename)
{
	string inputdata, totaldata;
	ifstream file(filename);
	if (file.is_open())
	{
		int counter = 0;
		while (getline(file, inputdata))
		{
			totaldata = totaldata + inputdata;
		}
		file.close();
	}
	return totaldata;
}

string SHA1string(string sha1)
{
	byte digest[SHA1::DIGESTSIZE];
	string message = sha1;
	SHA1 hash;
	hash.CalculateDigest(digest, (const byte*)message.c_str(), message.length());
	HexEncoder encoder;
	string output;
	encoder.Attach(new CryptoPP::StringSink(output));
	encoder.Put(digest, sizeof(digest));
	encoder.MessageEnd();
	return output;
}

void DecryptSession(string session, string privKey)
{
	string decodedEncHexEnSeshKey;
	StringSource ss(session, true, new HexDecoder(new StringSink(decodedEncHexEnSeshKey)));

	AutoSeededRandomPool rng;
	InvertibleRSAFunction parameters;
	parameters.GenerateRandomWithKeySize(rng, 1024);

	RSA::PrivateKey privateKey(parameters);
	string decodedPrivKey;

	StringSource ss2(privKey, true, (new HexDecoder(new StringSink(decodedPrivKey))));
	StringSource PrivKeySS(decodedPrivKey, true);		//load it into bytes
	privateKey.Load(PrivKeySS);		//load the private key

	RSAES_OAEP_SHA_Decryptor d(privateKey);
	string hexEnSeshkey;
	StringSource ss3(session, true, (new HexDecoder(new PK_DecryptorFilter(rng, d, (new StringSink(hexEnSeshkey))))));
	cout << "Decrypting the Session Key..." << endl;
	cout << "Session Key : " << hexEnSeshkey << endl;
	cout << "SHA-1 Hash Value : " << SHA1string(hexEnSeshkey) << endl;
	cout << "Decryption is complete..." << endl << endl;

	encodedSessionKey = hexEnSeshkey;
}

string send_recv(int socket, string message, string comments)
{
	int valread;
	char buffer[1024] = { 0 };
	send(socket, message.c_str(), strlen(message.c_str()) + 1, 0);
	cout << "[Client] Waiting/Receiving Message from Server... " << endl;
	valread = read(socket, buffer, 1024);
	cout << "[Message from Server] : ";
	printf("%s\n", buffer);
	cout << "[Details] " << comments << endl << endl;
	hashEncodedSession = buffer;
	encryptedmsg = buffer;
	return buffer;
}

void CFB_IDEA_Encryption(string keys, int sock)
{
	AutoSeededRandomPool prng;
	string decodedkey;
	StringSource s(keys, true, (new HexDecoder(
		new StringSink(decodedkey))
		) // StreamTransformationFilter
	); // StringSource

	SecByteBlock key((const byte*)decodedkey.data(), decodedkey.size());

	const byte iv[] = { 0x12,0x34,0x56,0x78,0x90,0xab,0xcd,0xef };

	string plain;
	string cipher, encoded, recovered;

	/*********************************\
	\*********************************/
	do
	{
		cout << "Enter Message to Server : ";
		getline(cin, plain);
		if (plain.size() > 1024)
		{
			cout << "[Client] Message Length is Exceed" << endl;
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
	catch (const CryptoPP::Exception& e)
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
	cout << "[Details] Message is Sent to Server" << endl << endl;
	encryptedmsg = send_recv(sock, encoded, "Received Hex Encoded Message from Server");
}

void sendpacket(int new_socket, string message)
{
	send(new_socket, message.c_str(), strlen(message.c_str()) + 1, 0);
}

void CFB_IDEA_Decryption(int socket, string keys, string encryptedmessage)
{
	AutoSeededRandomPool prng;
	string rawcipher, decodedkey;
	StringSource ss2(encryptedmessage, true,
		new HexDecoder(
			new StringSink(rawcipher)
		) // HexEncoder
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
			sendpacket(socket, encryptedmessage);
			exit(1);
		}

		cout << "\x1b[A" << "Decrypted Text : " << recovered << endl << endl;
	}
	catch (const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}
}

int main()
{
	char buffer[1024] = { 0 };
	string receive = "Client Received.";
	int sock = socket(), valread;
	cout << "[Client] Server is Successfully Connected!" << endl << endl;
	cout << "[Client] RSA Key is generating..." << endl << endl;

	keyGen();

	string privatekey = grabfilecontent("PrivateKey.txt");
	string publickey = grabfilecontent("PublicKey.txt");

	cout << "[Client] Public Key : " << publickey << endl;

	send_recv(sock, publickey, "Client --> Server | Public Key is Sent to Server");

	string SHA1PublicKey = SHA1string(publickey);
	cout << "[Client] SHA-1 Hash of Public Key : " << SHA1PublicKey << endl;

	send_recv(sock, SHA1PublicKey, "Client --> Server | SHA-1 Hash Value of Public Key is Sent to Server");
	
	cout << "Receiving Encrypted Session Key and Its Hashing Value From Server..." << endl << endl;

	string encryptedSessionKey = send_recv(sock, receive, "Received Encrypted Session Key from Server");

	send_recv(sock, receive, "Received SHA-1 Hash of Session Key from Server ");

	DecryptSession(encryptedSessionKey, privatekey);

	verify(SHA1string(encodedSessionKey), hashEncodedSession);

	cout << "IDEA KEY : ";
	cout << encodedSessionKey << endl << endl;

	bool loop = true;
	cin.ignore();
	do
	{
		CFB_IDEA_Encryption(encodedSessionKey, sock);
		CFB_IDEA_Decryption(sock, encodedSessionKey, encryptedmsg);
	} while (loop == true);
	return 0;
}
