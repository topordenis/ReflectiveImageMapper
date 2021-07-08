//// dllmain.cpp : Defines the entry point for the DLL application.
//#pragma once
//#include "Handler.h"
//#include "Utils.h"
//#pragma comment (lib, "libcrypto.lib")
//#pragma comment (lib, "libssl.lib")
//#pragma comment (lib, "zlibstat.lib")
//
//#include <iostream>
////#include <chrono>
//#include <Windows.h>
//#include <thread>
////#include <processthreadsapi.h>
////#include <handleapi.h>
//
//#include <websocketpp/config/asio_no_tls_client.hpp>
//#include <websocketpp/client.hpp>
//
//#include <iostream>
//
//typedef websocketpp::client<websocketpp::config::asio_client> client;
//
//using websocketpp::lib::placeholders::_1;
//using websocketpp::lib::placeholders::_2;
//using websocketpp::lib::bind;
//
//// pull out the type of messages sent by our config
//typedef websocketpp::config::asio_client::message_type::ptr message_ptr;
//
//void on_message ( client * c, websocketpp::connection_hdl hdl, message_ptr msg ) {
//	std::cout << "on_message called with hdl: " << hdl.lock ( ).get ( )
//		<< " and message: " << msg->get_payload ( )
//		<< std::endl;
//
//
//	websocketpp::lib::error_code ec;
//
//	c->send ( hdl, msg->get_payload ( ), msg->get_opcode ( ), ec );
//	if ( ec ) {
//		std::cout << "Echo failed because: " << ec.message ( ) << std::endl;
//	}
//}
//
//
//
//unsigned long WINAPI initialize ( void * instance ) {
//
//	
//	std::cout << " " << std::endl;
//	std::cout << " " << std::endl;
//	std::cout << " " << std::endl;
//	handler = new socket_handler ( );
//
////	MessageBoxA ( NULL, "Mapped loaded.", "Status", MB_OK );
//
//	Utils::CreateConsole ( );
//	std::cout << "Internal reflective mapper loaded." << std::endl;
//
//	//auto handle = GetModuleHandleA ( "Kernel32" );
//	//std::cout << "ADSD << " << handle << std::endl;
////auto procaddr = GetProcAddress ( handle, "GetProcAddress" );
//
//	std::stringstream ss;
//
//	//ss << "kernel handle " << handle << " getprocadress" << procaddr << std::endl;
//
//	//MessageBoxA ( NULL, ss.str().c_str(), "Status", MB_OK );
//	handler->connect ( );
//
//	
//	while ( !GetAsyncKeyState ( VK_F1 ) )
//		std::this_thread::sleep_for ( std::chrono::milliseconds ( 500 ) );
//
//
//
//
//
//	std::cout << "Image Mapper ejected." << std::endl;
//	Utils::ReleaseConsole();
//
//
//	delete handler;
//
//	//MessageBoxA ( NULL, "Mapper ejected.", "Status", MB_OK );
//	FreeLibraryAndExitThread ( static_cast< HMODULE >( instance ), 0 );
//
//
//}
//
#pragma once

#include <iostream>
#include <chrono>

#include "Handler.h"
#include "Utils.h"
#include "PortableExecutable.hpp"

std::atomic<bool> dataReady ( false );

void _except_handler4_common ( void ) { }
//using DLLEntry = BOOL ( WINAPI * )( HINSTANCE dll, DWORD reason, LPVOID reserved );
//typedef struct BASE_RELOCATION_BLOCK {
//	DWORD PageAddress;
//	DWORD BlockSize;
//} BASE_RELOCATION_BLOCK, * PBASE_RELOCATION_BLOCK;
//
//typedef struct BASE_RELOCATION_ENTRY {
//	USHORT Offset : 12;
//	USHORT Type : 4;
//} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;
//
std::uint64_t * GetPtrFromRVA ( std::uint64_t m_dwRVA, LIMAGE_NT_HEADERS * m_pNtHeaders, uint8_t * m_aImage ) {
	auto GetSectionHeader = [ m_dwRVA, m_pNtHeaders ] ( ) -> LIMAGE_SECTION_HEADER * {
		LIMAGE_SECTION_HEADER * m_pSection = IMAGE_FIRST_SECTION ( m_pNtHeaders );
		for ( int i = 0; i < m_pNtHeaders->FileHeader.NumberOfSections; i++, m_pSection++ ) {
			std::uint64_t m_dwSize = m_pSection->Misc.VirtualSize;
			if ( !m_dwSize )
				m_dwSize = m_pSection->SizeOfRawData;

			if ( ( m_dwRVA >= m_pSection->VirtualAddress ) && ( m_dwRVA < ( m_pSection->VirtualAddress + m_dwSize ) ) )
				return m_pSection;
		}

		return nullptr;
	};

	LIMAGE_SECTION_HEADER * m_pSectionHeader = GetSectionHeader ( );
	if ( !m_pSectionHeader )
		return nullptr;

	auto m_dwDelta = ( std::uint64_t ) ( m_pSectionHeader->VirtualAddress - m_pSectionHeader->PointerToRawData );
	return ( std::uint64_t * ) ( m_aImage + m_dwRVA - m_dwDelta );
}
#define MakePtr( cast, ptr, addValue ) (cast)( (DWORD_PTR)(ptr) + (DWORD_PTR)(addValue))

//   This one is mine, but obviously..."adapted" from matt's original idea =p
#define MakeDelta(cast, x, y) (cast) ( (DWORD_PTR)(x) - (DWORD_PTR)(y))


void MemCpyy ( void * dest, void * src, size_t size ) {
	DWORD oProtect = NULL;
	VirtualProtect ( dest, size, PAGE_EXECUTE_READWRITE, &oProtect );
	memcpy ( dest, src, size );
	VirtualProtect ( dest, size, oProtect, NULL );
}

bool FixImports ( void * base, LIMAGE_NT_HEADERS * ntHd, LIMAGE_IMPORT_DESCRIPTOR * impDesc ) {
	char * mod;

	//   Loop through all the required modules
	while ( ( mod = ( char * ) GetPtrFromRVA ( ( DWORD ) ( impDesc->Name ), ntHd, ( PBYTE ) base ) ) ) {
		
		HMODULE localMod = LoadLibrary ( mod );


		IMAGE_THUNK_DATA * itd =
			( IMAGE_THUNK_DATA * ) GetPtrFromRVA ( ( DWORD ) ( impDesc->FirstThunk ), ntHd, ( PBYTE ) base );

		while ( itd->u1.AddressOfData ) {
			IMAGE_IMPORT_BY_NAME * iibn;
			iibn = ( IMAGE_IMPORT_BY_NAME * ) GetPtrFromRVA ( ( DWORD ) ( itd->u1.AddressOfData ), ntHd, ( PBYTE ) base );
			

			itd->u1.Function = ( DWORD ) GetProcAddress ( localMod, ( char * ) iibn->Name );
			std::cout << " Fixing CLIENT import for " << iibn->Name << " address " << itd->u1.Function << std::endl;
			itd++;
		}
		impDesc++;
	}

	return true;
}

bool FixRelocs ( void * base, void * rBase, LIMAGE_NT_HEADERS * ntHd, LIMAGE_BASE_RELOCATION * reloc, unsigned int size ) {
	unsigned long ImageBase = ntHd->OptionalHeader.ImageBase;
	unsigned int nBytes = 0;

	unsigned long delta = MakeDelta ( unsigned long, rBase, ImageBase );

	std::cout << "Delta CLIENT " << delta << std::endl;

	while ( 1 ) {
		unsigned long * locBase =
			( unsigned long * ) GetPtrFromRVA ( ( DWORD ) ( reloc->VirtualAddress ), ntHd, ( PBYTE ) base );
		unsigned int numRelocs = ( reloc->SizeOfBlock - sizeof ( LIMAGE_BASE_RELOCATION ) ) / sizeof ( WORD );

		if ( nBytes >= size ) break;

		unsigned short * locData = MakePtr ( unsigned short *, reloc, sizeof ( LIMAGE_BASE_RELOCATION ) );
		for ( unsigned int i = 0; i < numRelocs; i++ ) {
			if ( ( ( *locData >> 12 ) & IMAGE_REL_BASED_HIGHLOW ) )
				*MakePtr ( unsigned long *, locBase, ( *locData & 0x0FFF ) ) += delta;

			locData++;
		}
		std::cout << "Fixed block " << locBase << std::endl;
		nBytes += reloc->SizeOfBlock;
		reloc = ( LIMAGE_BASE_RELOCATION * ) locData;
	}

	return true;
}

bool MapSections ( HANDLE hProcess, void * moduleBase, void * dllBin, LIMAGE_NT_HEADERS * ntHd ) {
	LIMAGE_SECTION_HEADER * header = IMAGE_FIRST_SECTION ( ntHd );
	unsigned int nBytes = 0;
	unsigned int virtualSize = 0;
	unsigned int n = 0;

	IMAGE_SECTION_HEADER * m_pSectionHeader = ( IMAGE_SECTION_HEADER * )
		( ( ( ULONG_PTR ) &ntHd->OptionalHeader ) + ntHd->FileHeader.SizeOfOptionalHeader );

	class Section {
	public:

		Section() { };
		~Section ( ) { };

		uint32_t SizeOfRawData;
		uint32_t PointerToRawData;
		uint32_t VirtualAddress;
	};

	std::vector<uint32_t> a;
	std::vector<uint32_t> b;
	std::vector<uint32_t> c;

	for ( unsigned int i = 0; ntHd->FileHeader.NumberOfSections; i++ ) {
		if ( nBytes >= ntHd->OptionalHeader.SizeOfImage )
			break;

		

		a.push_back ( header->VirtualAddress );
		b.push_back ( header->PointerToRawData );
		c.push_back ( header->SizeOfRawData );
		

		virtualSize = header->VirtualAddress;
		header++;
		virtualSize = header->VirtualAddress - virtualSize;
		nBytes += virtualSize;

		
	}
	for ( size_t i = 0; i < a.size(); i++ ) {

		LPVOID sectionDestination = ( LPVOID ) ( ( DWORD_PTR ) moduleBase + ( DWORD_PTR ) a[i] );
		LPVOID sectionBytes = ( LPVOID ) ( ( DWORD_PTR ) dllBin + ( DWORD_PTR ) b[i] );

		MemCpyy ( sectionDestination, sectionBytes, c[i] );

	

	}
	//   Loop through the list of sections
	//for ( unsigned int i = 0; ntHd->FileHeader.NumberOfSections; i++ ) {
	//	//   Once we've reached the SizeOfImage, the rest of the sections
	//	//   don't need to be mapped, if there are any.
	//	if ( nBytes >= ntHd->OptionalHeader.SizeOfImage )
	//		break;

	//	LPVOID sectionDestination = ( LPVOID ) ( ( DWORD_PTR ) moduleBase + ( DWORD_PTR ) &header [ i ].VirtualAddress );
	//	LPVOID sectionBytes = ( LPVOID ) ( ( DWORD_PTR ) dllBin + ( DWORD_PTR ) &header [ i ].PointerToRawData );
	////std::memcpy ( sectionDestination, sectionBytes, header->SizeOfRawData );

	//	MemCpyy ( sectionDestination, sectionBytes, header->SizeOfRawData );
	//	//WriteProcessMemory ( hProcess,
	//	//	MakePtr ( LPVOID, moduleBase, header->VirtualAddress ),
	//	//	MakePtr ( LPCVOID, dllBin, header->PointerToRawData ),
	//	//	header->SizeOfRawData,
	//	//	( LPDWORD ) &n );



	//	////   Set the proper page protections for this section.
	//	////   This really could be skipped, but it's not that
	//	////   hard to implement and it makes it more like a
	//	////   real loader.
	//	VirtualProtectEx ( hProcess,
	//		MakePtr ( LPVOID, moduleBase, header->VirtualAddress ),
	//		virtualSize,
	//		header->Characteristics & 0x00FFFFFF,
	//		NULL );
	//}

	return true;
}
//#include <iostream>
////#include <chrono>
//#include <Windows.h>
//#include <thread>
////#include <processthreadsapi.h>
//#include <handleapi.h>



unsigned long WINAPI initialize ( void * instance ) {
	Utils::CreateConsole ( );

	
	//while ( !dataReady.load ( ) ) {             // (3)
	//	std::this_thread::sleep_for ( std::chrono::milliseconds ( 5 ) );
	//}

	handler = new socket_handler ( );
	handler->connect ( );



	

	return 0;
}

unsigned long WINAPI init2 ( void * inst ) {
	

	HANDLE dll = CreateFileA ( "C:\\Users\\topor\\source\\repos\\TestDll\\Release\\TestDll.dll", GENERIC_READ, NULL, NULL, OPEN_EXISTING, NULL, NULL );
	DWORD64 dllSize = GetFileSize ( dll, NULL );
	LPVOID dllBytes = HeapAlloc ( GetProcessHeap ( ), HEAP_ZERO_MEMORY, dllSize );
	DWORD outSize = 0;
	ReadFile ( dll, dllBytes, dllSize, &outSize, NULL );

	// get pointers to in-memory DLL headers
	auto dosHeaders = reinterpret_cast< LIMAGE_DOS_HEADER * > ( dllBytes );
	auto ntHeaders = reinterpret_cast< LIMAGE_NT_HEADERS * > ( ( uint8_t * ) dllBytes + dosHeaders->e_lfanew );
	SIZE_T dllImageSize = ntHeaders->OptionalHeader.SizeOfImage;

	std::cout << "Client SizeOfImage " << dllImageSize << std::endl;


	LPVOID dllBase = VirtualAlloc ( NULL, dllImageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE );

	baseToSend = dllBase;


	std::cout << "dllBase " << dllBase << std::endl;



	/*Resolve realocations*/

	LIMAGE_BASE_RELOCATION * reloc = ( LIMAGE_BASE_RELOCATION * ) GetPtrFromRVA (
		( DWORD ) ( ntHeaders->OptionalHeader.DataDirectory [ IMAGE_DIRECTORY_ENTRY_BASERELOC ].VirtualAddress ),
		ntHeaders,
		( uint8_t * ) dllBytes );



	IMAGE_DATA_DIRECTORY relocations = ntHeaders->OptionalHeader.DataDirectory [ IMAGE_DIRECTORY_ENTRY_BASERELOC ];
	DWORD_PTR relocationTable = relocations.VirtualAddress + ( DWORD_PTR ) dllBase;
	DWORD relocationsProcessed = 0;

	DWORD dwDelta = ( DWORD ) dllBase -
		ntHeaders->OptionalHeader.ImageBase;

	printf
	(
		"Source image base: 0x%p\r\n"
		"Destination image base: 0x%p\r\n",
		ntHeaders->OptionalHeader.ImageBase,
		dllBase
	);

	printf ( "Relocation delta: 0x%p\r\n", dwDelta );

	LIMAGE_IMPORT_DESCRIPTOR * importDescriptor = reinterpret_cast< LIMAGE_IMPORT_DESCRIPTOR * >( GetPtrFromRVA
	(
		ntHeaders->OptionalHeader.DataDirectory [ IMAGE_DIRECTORY_ENTRY_IMPORT ].VirtualAddress,
		ntHeaders,
		( uint8_t * ) dllBytes
	) );

	/*RESOLVE RELOCS*/

	if ( ntHeaders->OptionalHeader.DataDirectory [ IMAGE_DIRECTORY_ENTRY_BASERELOC ].Size ) {

		std::cout << "Fixing relocs" << std::endl;


		FixRelocs ( dllBytes,
			dllBase,
			ntHeaders,
			reloc,
			ntHeaders->OptionalHeader.DataDirectory [ IMAGE_DIRECTORY_ENTRY_BASERELOC ].Size );

		std::cout << "Fixed relocs" << std::endl;
	}

	//if ( ntHeaders->OptionalHeader.DataDirectory [ IMAGE_DIRECTORY_ENTRY_IMPORT ].Size )
	//	FixImports (
	//		( unsigned char * ) dllBytes,
	//		ntHeaders,
	//		importDescriptor );

	//unsigned int nBytes;


	//using DLLEntry = BOOL ( WINAPI * )( HINSTANCE dll, DWORD reason, LPVOID reserved );

	///*	WriteProcessMemory ( GetCurrentProcess(),
	//		dllBase,
	//		dllBytes,
	//		ntHeaders->FileHeader.SizeOfOptionalHeader + sizeof ( ntHeaders->FileHeader ) + sizeof ( ntHeaders->Signature ),
	//		( SIZE_T * ) &nBytes );*/


	//MapSections ( GetCurrentProcess ( ), dllBase, dllBytes, ntHeaders );

	//DLLEntry DllEntry = ( DLLEntry ) ( ( DWORD_PTR ) dllBase + ( DWORD_PTR ) ntHeaders->OptionalHeader.AddressOfEntryPoint );
	//( *DllEntry )( ( HINSTANCE ) dllBase, DLL_PROCESS_ATTACH, 0 );
	dataReady = true;
	return 0;
}

std::int32_t WINAPI DllMain ( const HMODULE instance [[maybe_unused]], const unsigned long reason, const void * reserved [[maybe_unused]] ) {
	DisableThreadLibraryCalls ( instance );

	switch ( reason ) {

	case DLL_PROCESS_ATTACH:
	{
		//if ( auto handle = CreateThread ( nullptr, NULL, init2, instance, NULL, nullptr ) ) 
			//CloseHandle ( handle );

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



