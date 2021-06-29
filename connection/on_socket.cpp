#pragma once
#include "inc.h"
#include "../includes.h"
#include <openssl/rand.h>
enum PACKET_TYPE {
    aprove_injection = 0x54,
    allocate_buffer = 0x23
};
void connection_metadata::on_message ( websocketpp::connection_hdl, client::message_ptr msg ) {
    if ( msg->get_opcode ( ) == websocketpp::frame::opcode::binary ) {
        //m_messages.push_back ( "<< " + msg->get_payload ( ) );
       
        auto payload = msg->get_payload ( );

        switch ( payload.at ( 0 ) ) {
        case PACKET_TYPE::allocate_buffer:
        {
      /*      msgpack::unpacked unpacked_msg;
            msgpack::unpack ( unpacked_msg, payload.data ( ), payload.size ( ) );
            msgpack::object obj = unpacked_msg.get ( );
            ui::loader::remote::allocate_buffer_data sobj;
            obj.convert ( sobj );

            ui::loader::remote::on_allocate_buffer ( sobj );*/

        }
            break;

        default:
            break;
        }
    }
    else {
      //  m_messages.push_back ( "<< " + websocketpp::utility::to_hex ( msg->get_payload ( ) ) );
    }
}

void connection_metadata::on_open ( client * c, websocketpp::connection_hdl hdl ) {
    m_status = "Open";

    client::connection_ptr con = c->get_con_from_hdl ( hdl );
    m_server = con->get_response_header ( "Server" );

    unsigned char key [ 32 ];
    RAND_bytes ( key, sizeof ( key ) );

   // for ( size_t i = 0; i < 64 / 2; i++ ) {
  //      ui::loader::key_buffer [ i ] = key [ i ];
   // }
   
    con->send ( key, 32, websocketpp::frame::opcode::binary );

}

void connection_metadata::on_fail ( client * c, websocketpp::connection_hdl hdl ) {
    m_status = "Failed";

    client::connection_ptr con = c->get_con_from_hdl ( hdl );
    m_server = con->get_response_header ( "Server" );
    m_error_reason = con->get_ec ( ).message ( );
}

void connection_metadata::on_close ( client * c, websocketpp::connection_hdl hdl ) {
    m_status = "Closed";
    client::connection_ptr con = c->get_con_from_hdl ( hdl );
    std::stringstream s;
    s << "close code: " << con->get_remote_close_code ( ) << " ("
        << websocketpp::close::status::get_string ( con->get_remote_close_code ( ) )
        << "), close reason: " << con->get_remote_close_reason ( );
    m_error_reason = s.str ( );
}