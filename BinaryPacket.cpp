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

    AES_KEY enc_key;
    AES_set_encrypt_key ( key, 32, &enc_key );
    AES_cbc_encrypt ( ( unsigned char * ) this->buffer.data(), ( unsigned char * ) this->buffer.data ( ), this->buffer.size(), &enc_key, Utils::OTPKey ( 30 ).data ( ), AES_ENCRYPT );

    this->encrypted = true;
}

void BinaryPacket::decrypt ( unsigned char * key ) {

    AES_KEY enc_key;
    AES_set_decrypt_key ( key, 32, &enc_key );
    AES_cbc_encrypt ( ( unsigned char * ) this->buffer.data ( ), ( unsigned char * ) this->buffer.data ( ), this->buffer.size ( ), &enc_key, Utils::OTPKey(30).data(), AES_DECRYPT );

    this->encrypted = false;
}
void BinaryPacket::send ( ) {
    websocketpp::lib::error_code ec;

    auto con = handler->m_endpoint.get_con_from_hdl ( handle, ec );
    if ( ec ) {
        std::cout << "> Failed sending binary packet: " << ec.message ( ) << std::endl;
        return;
    }

    msgpack::sbuffer sbuf;
    msgpack::pack ( sbuf, *this );

    con->send ( sbuf.data ( ), sbuf.size ( ) );

}


