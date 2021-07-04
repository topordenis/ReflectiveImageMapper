#pragma once
#include <vector>
#include <msgpack.hpp>

enum PacketType {
	PACKET_KEY,
	PACKET_LOGIN
};

class BinaryPacket {
public:
	BinaryPacket ( websocketpp::connection_hdl client_handle );
	BinaryPacket ( ) { };

	
	~BinaryPacket ( );

private:

	int type;
	std::string buffer;
	bool encrypted;


	websocketpp::connection_hdl handle;
public:
	void decrypt ( unsigned char * key );
	void send ( );
	void encrypt ( unsigned char* key );

	MSGPACK_DEFINE ( type, buffer, encrypted );

public: 
	msgpack::object get ( );

public:

	PacketType getType ( ) {
		return ( PacketType ) type;
	}


};

