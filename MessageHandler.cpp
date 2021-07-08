#pragma once
#include "Handler.h"
#include "RemoteMapper.h"
static BinaryPacket sectionsPacket;
static LPVOID dllBase;

using DLLEntry = BOOL ( WINAPI * )( HINSTANCE dll, DWORD reason, LPVOID reserved );


static std::uintptr_t allocated_size = 0;
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

#define MakePtr( cast, ptr, addValue ) (cast)( (DWORD_PTR)(ptr) + (DWORD_PTR)(addValue))

//   This one is mine, but obviously..."adapted" from matt's original idea =p
#define MakeDelta(cast, x, y) (cast) ( (DWORD_PTR)(x) - (DWORD_PTR)(y))


void MemCpy ( void * dest, void * src, size_t size ) {
    DWORD oProtect = NULL;
    VirtualProtect ( dest, size, PAGE_EXECUTE_READWRITE, &oProtect );
    memcpy ( dest, src, size );
    VirtualProtect ( dest, size, oProtect, NULL );
}
void socket_handler::message_handle ( websocketpp::connection_hdl, client::message_ptr msg ) {
  
   // std::cout << "on_message called "
      //        << " and message (" << msg->get_payload().size() << "): " << msg->get_payload()
       //       << std::endl;
    
    try {
        if ( msg->get_opcode ( ) == websocketpp::frame::opcode::binary ) {
            std::cout << "New packet recived... " << std::endl;
            try {
                BinaryPacket packet;

                msgpack::unpacked unpacked_msg;
                msgpack::unpack ( unpacked_msg, msg->get_payload ( ).data ( ), msg->get_payload ( ).size ( ) );
                msgpack::object obj = unpacked_msg.get ( );


                obj.convert ( packet );
                std::cout << "Packet type: " << ( int ) packet.getType ( ) << " Encrypted: " << packet.encrypted << " Size: " << packet.buffer.size ( ) << " Original size: " << packet.original_size << std::endl;



                if ( packet.encrypted ) {

                    packet.decrypt ( ( unsigned char * ) this->m_key.data ( ) );

                }


                switch ( packet.getType ( ) ) {
                case PacketType::PACKET_KEY:
                {
                    std::cout << "Recived encryption RSA Key " << websocketpp::utility::to_hex ( packet.buffer.data ( ) ) << std::endl;

                    this->m_key.resize ( 32 );
                    std::memcpy ( ( char * ) this->m_key.data ( ), packet.buffer.data ( ), packet.buffer.size ( ) );


                    BinaryPacket inj_packet;
                    inj_packet.setType ( PacketType::PACKET_REQUEST_INJECTION );

                    std::cout << "Sent request to continue injection..." << std::endl;
                    inj_packet.send ( );
                }
                break;
                case PacketType::PACKET_ALLOC_SIZE:
                {

                    auto obj = packet.get ( );
                    std::uint32_t m_dwAllocationSize;

                    obj.convert ( m_dwAllocationSize );

                    std::cout << "Recived PACKET_ALLOC_SIZE m_dwAllocationSize = " << m_dwAllocationSize << std::endl;

                    dllBase = VirtualAlloc ( NULL, m_dwAllocationSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE );
                    std::cout << "dllBase SERVER " << ( std::uint64_t ) dllBase << std::endl;
                    
                   
                   
                    std::stringstream sbuf;
                    msgpack::pack ( sbuf, ( std::uint64_t ) dllBase );

                    BinaryPacket alloc_packet;
                    alloc_packet.buffer = sbuf.str ( );

                   // alloc_packet.pack ( (std::uint64_t) baseToSend );
                    alloc_packet.setType ( PacketType::PACKET_ALLOC_ADDRESS );
                    alloc_packet.send ( );



                }

                break;

                case PacketType::PACKET_IMPORTS_LIST:
                {
                  
                    std::vector< std::pair<std::string, std::string> > list;
                  
                    msgpack::unpacked msg;
                    msgpack::unpack ( msg, packet.buffer.data ( ), packet.buffer.size ( ) );


                    msg.get ( ).convert ( list );



                       std::cout << "list.size() " << list.size ( ) << std::endl;

                    std::vector< std::uint32_t > m_aImportAddresses;

                    for ( auto & imp : list ) {

                        auto hModule = GetModuleHandleA ( imp.second.c_str ( ) );
                        if (!hModule )
                            hModule = LoadLibrary ( imp.second.c_str ( ) );


                        std::uint32_t address = ( DWORD ) GetProcAddress ( hModule, imp.first.c_str ( ) );
                        std::cout << " Fixing SERVER import for " << imp.first << " address " << address << std::endl;

                        m_aImportAddresses.push_back ( address );


                    }
                    BinaryPacket importAddresses;
                    importAddresses.pack ( m_aImportAddresses );
                    importAddresses.setType ( PacketType::PACKET_IMPORTS_ADDRESSES );
                    importAddresses.send ( );
                }
                break;
                case PacketType::PACKET_SECTIONS:
                {
                    std::cout << "Recived PACKET_SECTIONS size" << packet.buffer.size ( ) << std::endl;
                    sectionsPacket = packet;
                    std::cout << "sectionsPacket saved for later use" << packet.buffer.size ( ) << std::endl;

                    BinaryPacket success;
                 
                    success.setType ( PacketType::PACKET_RECIVED_SECTIONS );
                    success.send ( );

                    
                }
                break;
                case PacketType::PACKET_MAPPED_IMAGE:
                {
                    PacketCPEData SectionsData;
                    
                    std::cout << "Recived PACKET_MAPPED_IMAGE size" << packet.buffer.size()  << std::endl;
                
                    msgpack::unpacked sections;
                    msgpack::unpack ( sections, sectionsPacket.buffer.data ( ), sectionsPacket.buffer.size ( ) );

                   // msgpack::unpacked mapped_image;
                   // msgpack::unpack ( mapped_image, packet.buffer.data ( ), packet.buffer.size ( ) );
                    

                    std::vector< std::uint8_t > MappedImageBuff;
                    MappedImageBuff.resize ( packet.buffer.size ( ) );
                    std:memcpy ( MappedImageBuff.data ( ), packet.buffer.data ( ), packet.buffer.size ( ) );




                    if ( sections.get ( ).convert_if_not_nil ( SectionsData ) ) {

                        std::cout << " A mers smecheria pana aici doar de injectat a ramas :)" << std::endl;
                        std::cout << "Entry point from server " << SectionsData.m_dwEntry << std::endl;

                        unsigned int nBytes = 0;
                        unsigned int virtualSize = 0;
                        unsigned int n = 0;
                     
                        for ( auto & section : SectionsData.m_aSections ) {

                            LPVOID sectionDestination = ( LPVOID ) ( ( DWORD_PTR ) dllBase + ( DWORD_PTR ) section.m_iVirtualAddress );
                            LPVOID sectionBytes = ( LPVOID ) ( ( DWORD_PTR ) MappedImageBuff.data ( ) + ( DWORD_PTR ) section.m_iPtrToRaw );
                        
                            std::cout << "Mapped section " << std::endl;

                            MemCpy ( sectionDestination, sectionBytes, section.m_iSizeOfRaw );
                        }

                        std::cout << "Sections were mapped succefully." << std::endl;
                        std::cout << "Attemp calling entrypoint." << std::endl;

                        DLLEntry DllEntry = ( DLLEntry ) ( ( DWORD_PTR ) dllBase + ( DWORD_PTR ) SectionsData.m_dwEntry );
                        ( *DllEntry )( ( HINSTANCE ) dllBase, DLL_PROCESS_ATTACH, 0 );

                        std::cout << "post call." << std::endl;
                    }
                    else {
                        std::cout << "Failed unpacking buffer.";
                    }
                  
                    


                  
                }
                break;
                default:
                    break;
                }
            
            }
            catch ( int err ) {
                std::cout << "error reciving packet" << std::endl;
            }

        }
       
        //server.send ( hdl, msg->get_payload ( ), msg->get_opcode ( ) );
    }
    catch ( websocketpp::exception const & e ) {
        std::cout << "Echo failed because: "
            << "(" << e.what ( ) << ")" << std::endl;
    }
}
