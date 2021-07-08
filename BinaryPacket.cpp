#include "Handler.h"
#include "Utils.h"
#include <openssl/aes.h>
#include <openssl/rand.h>


BinaryPacket::BinaryPacket ( connection_hdl client_handle ) {
    handle = client_handle;
}

BinaryPacket::~BinaryPacket ( ) {

}

void BinaryPacket::encrypt ( unsigned char * key ) {

    original_size = this->buffer.size ( );

    std::string enc_out; enc_out.resize ( original_size + 16 - ( original_size % 16 ) );


    unsigned char local_vector [ AES_BLOCK_SIZE ];
    memcpy ( local_vector, Utils::OTPKey ( 30 ).data ( ), AES_BLOCK_SIZE );

    AES_KEY dec_key;


    AES_set_encrypt_key ( key, 256, &dec_key );
    AES_cbc_encrypt ( ( unsigned char * ) this->buffer.data ( ), ( unsigned char * ) enc_out.data ( ), enc_out.size ( ), &dec_key, local_vector, AES_ENCRYPT );



    this->encrypted = true;

}

void BinaryPacket::decrypt ( unsigned char * key ) {


    std::string dec_out;
    dec_out.resize ( original_size );


    unsigned char local_vector [ AES_BLOCK_SIZE ];
    memcpy ( local_vector, Utils::OTPKey ( 00 ).data ( ), AES_BLOCK_SIZE );

    AES_KEY dec_key;


    AES_set_decrypt_key ( key, 256, &dec_key );
    AES_cbc_encrypt ( ( unsigned char * ) this->buffer.data ( ), ( unsigned char * ) dec_out.data ( ), original_size, &dec_key, local_vector, AES_DECRYPT );

    this->buffer = dec_out;

    this->encrypted = false;
}
void BinaryPacket::send ( ) {
    websocketpp::lib::error_code ec;

    auto con = handler->m_client.get_con_from_hdl ( handler->m_hdl, ec );
    if ( ec ) {
        std::cout << "> Failed sending binary packet: " << ec.message ( ) << std::endl;
        return;
    }


    msgpack::sbuffer sbuf;
    msgpack::pack ( sbuf, *this );

    con->send ( sbuf.data ( ), sbuf.size ( ) );


}

msgpack::object BinaryPacket::get ( ) {
    msgpack::unpacked msg;
    msgpack::unpack ( msg, buffer.data ( ), buffer.size ( ) );

    return msg.get ( );

}



