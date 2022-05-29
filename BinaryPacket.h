#pragma once
#include <vector>
#include <msgpack.hpp>

enum class PacketType :  int {
	PACKET_KEY,
	PACKET_LOGIN,
	PACKET_REQUEST_INJECTION,
	PACKET_ALLOC_SIZE,
	PACKET_ALLOC_ADDRESS,
	PACKET_IMPORTS_LIST,
	PACKET_IMPORTS_ADDRESSES,
	PACKET_SECTIONS,
	PACKET_MAPPED_IMAGE,
	PACKET_RECIVED_SECTIONS
};

class BinaryPacket {
public:
	BinaryPacket ( websocketpp::connection_hdl client_handle );
	BinaryPacket ( ) { };

	
	~BinaryPacket ( );

public:

	int type;
	std::string buffer;

	bool encrypted;

	size_t original_size;


	websocketpp::connection_hdl handle;
public:

	void decrypt ( unsigned char * key );
	void send ( );
	void encrypt ( unsigned char * key );

	template < typename T>
	void pack ( const T & v ) {


		msgpack::sbuffer stream;

		msgpack::pack ( stream, v );

		buffer.resize ( stream.size ( ) );

		std::memcpy ( buffer.data ( ), stream.data ( ), stream.size ( ) );



	}



public:

	MSGPACK_DEFINE ( type, buffer, encrypted, original_size );

public:
	msgpack::object get ( );

public:

	PacketType getType ( ) {
		return static_cast< PacketType >( type );
	}
	void setType ( PacketType t ) {
		type = static_cast< int >( t );
	}
};


class InjectPacket {
public:
	InjectPacket ( ) { };
	std::uint64_t m_dwEntry = 0x0;
	std::vector< std::uint8_t > buffer;

	MSGPACK_DEFINE ( m_dwEntry, buffer );
};

class PacketCSection {
public:
	PacketCSection ( ) { };

	std::uint32_t m_iVirtualAddress;
	std::uint32_t m_iPtrToRaw;
	std::uint32_t m_iSizeOfRaw;
	MSGPACK_DEFINE ( m_iVirtualAddress, m_iPtrToRaw, m_iSizeOfRaw );
};


class PacketCPEData {
public:
	PacketCPEData ( ) { }

	std::uint64_t m_dwEntry = 0x00;
	std::vector< PacketCSection > m_aSections = { };

	MSGPACK_DEFINE ( m_dwEntry, m_aSections );
};

class PacketImport {
public:
	PacketImport ( ) { };


	std::string m_function;
	std::vector< std::string > m_Functions = { };

	MSGPACK_DEFINE ( m_function, m_Functions );
};
