// dllmain.cpp : Defines the entry point for the DLL application.
#pragma once
#include "Handler.h"
#include "Utils.h"
#pragma comment (lib, "libcrypto.lib")
#pragma comment (lib, "libssl.lib")
#pragma comment (lib, "zlibstat.lib")

#include <iostream>
//#include <chrono>
#include <Windows.h>
#include <thread>
//#include <processthreadsapi.h>
//#include <handleapi.h>

#include <websocketpp/config/asio_no_tls_client.hpp>
#include <websocketpp/client.hpp>

#include <iostream>

typedef websocketpp::client<websocketpp::config::asio_client> client;

using websocketpp::lib::placeholders::_1;
using websocketpp::lib::placeholders::_2;
using websocketpp::lib::bind;

// pull out the type of messages sent by our config
typedef websocketpp::config::asio_client::message_type::ptr message_ptr;

void on_message ( client * c, websocketpp::connection_hdl hdl, message_ptr msg ) {
	std::cout << "on_message called with hdl: " << hdl.lock ( ).get ( )
		<< " and message: " << msg->get_payload ( )
		<< std::endl;


	websocketpp::lib::error_code ec;

	c->send ( hdl, msg->get_payload ( ), msg->get_opcode ( ), ec );
	if ( ec ) {
		std::cout << "Echo failed because: " << ec.message ( ) << std::endl;
	}
}



unsigned long WINAPI initialize ( void * instance ) {
	std::cout << " " << std::endl;
	std::cout << " " << std::endl;
	std::cout << " " << std::endl;
	handler = new socket_handler ( );

	//MessageBoxA ( NULL, "Mapped loaded.", "Status", MB_OK );

	//Utils::CreateConsole ( );
	std::cout << "Internal reflective mapper loaded." << std::endl;

//	MessageBoxA ( NULL, "Mapper Image injected.", "Status", MB_OK );

	handler->connect ( );

	
	while ( !GetAsyncKeyState ( VK_F1 ) )
		std::this_thread::sleep_for ( std::chrono::milliseconds ( 500 ) );





	std::cout << "Image Mapper ejected." << std::endl;
	//Utils::ReleaseConsole();


	delete handler;

	//MessageBoxA ( NULL, "Mapper ejected.", "Status", MB_OK );
	FreeLibraryAndExitThread ( static_cast< HMODULE >( instance ), 0 );


}

std::int32_t WINAPI DllMain ( const HMODULE instance [[maybe_unused]], const unsigned long reason, const void * reserved [[maybe_unused]] ) {
	DisableThreadLibraryCalls ( instance );

	switch ( reason ) {
	case DLL_PROCESS_ATTACH:
	{
		if ( auto handle = CreateThread ( nullptr, NULL, initialize, instance, NULL, nullptr ) )
			CloseHandle ( handle );

		break;
	}

	case DLL_PROCESS_DETACH:
	{
	
		break;
	}
	}

	return true;
}

