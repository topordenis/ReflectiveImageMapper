#pragma once
#include "Handler.h"


void socket_handler::on_open ( ) {
    status = CLIENT_STATUS::CONNECTED;
    std::cout << "Connection oppened succesfully." << std::endl;

}

void socket_handler::on_close (  ) {
    status = CLIENT_STATUS::CLOSED;

    std::cout << "Connection closed succesfully." << std::endl;
}
void socket_handler::on_fail (  ) {
    status = CLIENT_STATUS::CLOSED;
    std::cout << "Connection failed succesfully." << std::endl;
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
                BinaryPacket packet;

                msgpack::unpacked unpacked_msg;
                msgpack::unpack ( unpacked_msg, msg->get_payload().data ( ), msg->get_payload ( ).size ( ) );
                msgpack::object obj = unpacked_msg.get ( );
                
                obj.convert ( packet );

                switch (  packet.getType() ) {
                case PacketType::PACKET_KEY:

                    break;

                default:
                    break;
                }
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
