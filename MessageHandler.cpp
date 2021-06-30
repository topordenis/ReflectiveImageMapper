#pragma once
#include "Handler.h"


void socket_handler::on_open ( client * c, connection_hdl hdl ) {
    status = CLIENT_STATUS::CONNECTED;

}

void socket_handler::on_close ( client * c, connection_hdl hdl ) {
    status = CLIENT_STATUS::CLOSED;

}
void socket_handler::on_fail ( client * c, connection_hdl hdl ) {
    status = CLIENT_STATUS::CLOSED;

}
// Define a callback to handle incoming messages
void socket_handler::message_handle ( websocketpp::connection_hdl, client::message_ptr msg ) {
    /*std::cout << "on_message called with hdl: " << hdl.lock().get()
              << " and message (" << msg->get_payload().size() << "): " << msg->get_payload()
              << std::endl;
    */
    try {
        if ( msg->get_opcode ( ) == websocketpp::frame::opcode::binary ) {

            try {

            }
            catch ( int err ) {

            }

        }
       
        //server.send ( hdl, msg->get_payload ( ), msg->get_opcode ( ) );
    }
    catch ( websocketpp::exception const & e ) {
        std::cout << "Echo failed because: "
            << "(" << e.what ( ) << ")" << std::endl;
    }
}
