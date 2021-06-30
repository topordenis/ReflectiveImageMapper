#pragma once
#include <vector>
#include "PacketType.h"
#include <msgpack.hpp>

enum PacketType {
	PACKET_KEY,
	PACKET_LOGIN
};

class BinaryPacket {
public:
	BinaryPacket ( websocketpp::connection_hdl client_handle );
	~BinaryPacket ( );

private:

	int type;
	std::vector<unsigned char> buffer;

	bool encrypted = false;


	websocketpp::connection_hdl handle;
public:
	void decrypt ( unsigned char * key );
	void send ( );
	void encrypt ( unsigned char* key );


public:

	MSGPACK_DEFINE ( type, buffer, encrypted );
};

