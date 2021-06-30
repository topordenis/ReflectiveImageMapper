// dllmain.cpp : Defines the entry point for the DLL application.

#include <iostream>
#include <chrono>
#include <Windows.h>
#include <thread>
#include <processthreadsapi.h>
#include <handleapi.h>

#include "img.h"

unsigned long WINAPI initialize ( void * instance ) {



	MessageBoxA ( NULL, "Dll propriu zis.", "dll injected", MB_OK );


	while ( !GetAsyncKeyState ( VK_END ) )
		std::this_thread::sleep_for ( std::chrono::milliseconds ( 500 ) );

	MessageBoxA ( NULL, "asdasdsadas", "dll ejected", MB_OK );
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

