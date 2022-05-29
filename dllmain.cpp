
#pragma once

#include "includes.h"



void WipePEGarbage ( uintptr_t base ) {
	auto dosHeaders = ( IMAGE_DOS_HEADER * ) ( base );
	auto pINH = ( IMAGE_NT_HEADERS * ) ( base + dosHeaders->e_lfanew );

	auto pSectionHeader = ( IMAGE_SECTION_HEADER * ) ( pINH + 1 );

	printf (  ( "[censored]ing the PE, base: 0x%p, size: 0x%X" ), base, pINH->OptionalHeader.SizeOfImage );

	auto dir = pINH->OptionalHeader.DataDirectory [ IMAGE_DIRECTORY_ENTRY_IMPORT ];
	auto iat = ( IMAGE_IMPORT_DESCRIPTOR * ) ( base + dir.VirtualAddress );

	for ( ; iat->Name; ++iat ) {
		auto modName = ( char * ) ( base + ( uintptr_t ) iat->Name );
		auto entry = ( IMAGE_THUNK_DATA64 * ) ( base + iat->OriginalFirstThunk );

		for ( uintptr_t index = 0; entry->u1.AddressOfData; index += sizeof ( uintptr_t ), ++entry ) {
			auto pImport = ( IMAGE_IMPORT_BY_NAME * ) ( base + entry->u1.AddressOfData );
			auto importName = pImport->Name;
			auto x =  ( "Wiping import %s" );
			printf ( x, importName );
			auto len = strlen ( importName );
			ZeroMemory ( importName, len );
		}

		auto x =  ( "Wiping import module %s" );
		printf ( x, modName );

		auto len = strlen ( modName );
		ZeroMemory ( modName, len );
	}

	for ( int i = 0; i < pINH->FileHeader.NumberOfSections; i++ ) {
		auto section = pSectionHeader [ i ];
		auto name = section.Name;
		auto rva = section.VirtualAddress;
		auto size = section.SizeOfRawData;

		auto secBase = ( uintptr_t ) base + rva;
		auto secEnd = secBase + size;

		if ( strstr ( ( const char * ) name,  ( ".rdata" ) ) ) {
			uintptr_t shitBase = 0;

			for ( uintptr_t ptr = secBase; ptr < secEnd - 4; ptr++ ) {
				auto str = ( char * ) ptr;
				if ( str [ 0 ] == 'G' && str [ 1 ] == 'C' && str [ 2 ] == 'T' && str [ 3 ] == 'L' ) // whatever that "GCTL" shit is, we gotta clean it up
					shitBase = ptr;
			}
			auto shitSize = 676; // magic number. Change if not enough
			if ( shitBase ) {
				ZeroMemory ( ( void * ) shitBase, shitSize );
				printf (  ( "Cleaned GCTL" ) );
			}
			else {
				printf (  ( "Couldn't find GCTL shit" ) );
			}
		}
		else if (
			strstr ( ( const char * ) name,  ( ".rsrc" ) )
			|| strstr ( ( const char * ) name,  ( ".reloc" ) )
			/*|| strstr((const char*)name, ".pdata")*/ ) // assuming we need exception support.
		{
			printf (( "Wiping section %s" ), name );
			ZeroMemory ( ( void * ) secBase, size );
		}
		else if ( strstr ( ( const char * ) name,  ( ".data" ) ) ) // this particular meme can be unstable
		{
			printf (  ( "Wiping C++ exception data" ) );
			ZeroMemory ( ( void * ) ( secEnd - 0x1B7 ), 0x1B7 );
			printf (  ( "Wiped." ) );
		}
	}

	ZeroMemory ( ( void * ) base, pINH->OptionalHeader.SizeOfHeaders );
	printf (  ( "Wiped the headers. Done!" ) );
}
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

	LIMAGE_SECTION_HEADER * section_header = IMAGE_FIRST_SECTION ( ntHd );
	std::string ceauder = "CE MAI FACE MATA?";


	std::string ceauder2 = "AXEUSSOFTWARE";
	for ( int i = 0; i < ntHd->FileHeader.NumberOfSections; i++ ) {
		if ( !strcmp ( ".reloc", ( char * ) section_header [ i ].Name ) ) {
			void * m_pDest = ( PBYTE ) base + section_header [ i ].PointerToRawData;
			for ( size_t i = 0; i < section_header [ i ].SizeOfRawData; i++ ) {
				if ( i < ceauder.size ( ) )
					( ( unsigned char * ) m_pDest ) [ i ] = ceauder.at ( i );
				else
					( ( unsigned char * ) m_pDest ) [ i ] = 0x0;
			}
			//memset ( m_pDest, 0, section_header [ i ].SizeOfRawData );
		}
		if ( !strcmp ( ".rsrc", ( char * ) section_header [ i ].Name ) ) {
			void * m_pDest = ( PBYTE ) base + section_header [ i ].PointerToRawData;
			for ( size_t i = 0; i < section_header [ i ].SizeOfRawData; i++ ) {
				if ( i < ceauder2.size ( ) )
					( ( unsigned char * ) m_pDest ) [ i ] = ceauder2.at ( i );
				else
					( ( unsigned char * ) m_pDest ) [ i ] = 0x0;
			}
			//memset ( m_pDest, 0, section_header [ i ].SizeOfRawData );
		}
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

	std::vector<unsigned char> pe_rawf;
	pe_rawf.resize ( outSize );
	std::memcpy (pe_rawf.data(), dllBytes, outSize );

	CloseHandle(dll);

	// get pointers to in-memory DLL headers
	auto dosHeaders = reinterpret_cast< LIMAGE_DOS_HEADER * > ( pe_rawf.data() );
	auto ntHeaders = reinterpret_cast< LIMAGE_NT_HEADERS * > ( ( uint8_t * ) pe_rawf.data() + dosHeaders->e_lfanew );
	SIZE_T dllImageSize = ntHeaders->OptionalHeader.SizeOfImage;

	std::cout << "Client SizeOfImage " << dllImageSize << std::endl;


	LPVOID dllBase = VirtualAlloc ( NULL, dllImageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE );

	baseToSend = dllBase;


	std::cout << "dllBase " << dllBase << std::endl;



	/*Resolve realocations*/

	LIMAGE_BASE_RELOCATION * reloc = ( LIMAGE_BASE_RELOCATION * ) GetPtrFromRVA (
		( DWORD ) ( ntHeaders->OptionalHeader.DataDirectory [ IMAGE_DIRECTORY_ENTRY_BASERELOC ].VirtualAddress ),
		ntHeaders,
		( uint8_t * ) pe_rawf.data() );



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
		( uint8_t * ) pe_rawf.data()
	) );

	auto entrypointcopy = ntHeaders->OptionalHeader.AddressOfEntryPoint;

	/*RESOLVE RELOCS*/

	if ( ntHeaders->OptionalHeader.DataDirectory [ IMAGE_DIRECTORY_ENTRY_BASERELOC ].Size ) {

		std::cout << "Fixing relocs" << std::endl;


		FixRelocs ( pe_rawf.data(),
			dllBase,
			ntHeaders,
			reloc,
			ntHeaders->OptionalHeader.DataDirectory [ IMAGE_DIRECTORY_ENTRY_BASERELOC ].Size );

		std::cout << "Fixed relocs" << std::endl;
	}

	if ( ntHeaders->OptionalHeader.DataDirectory [ IMAGE_DIRECTORY_ENTRY_IMPORT ].Size )
		FixImports (
			( unsigned char * ) pe_rawf.data(),
			ntHeaders,
			importDescriptor );

	std::string msg = "UserId=213&HWID=5315432555235325";
	///*
	//LIMAGE_SECTION_HEADER * m_pSection = IMAGE_FIRST_SECTION ( m_pNtHeaders );
	//	for ( int i = 0; i < m_pNtHeaders->FileHeader.NumberOfSections; i++, m_pSection++ ) {
	//*/
	//LIMAGE_SECTION_HEADER * m_pSection = IMAGE_FIRST_SECTION ( ntHeaders );
	//
	//DWORD sizeHeaders = offsetof ( IMAGE_NT_HEADERS, OptionalHeader );/* -ntHeaders->FileHeader.SizeOfOptionalHeader + ( ntHeaders->FileHeader.NumberOfSections * sizeof ( IMAGE_SECTION_HEADER ) );*/

	//std::cout << "sizeHeaders " << sizeHeaders << std::endl;

	//IMAGE_SECTION_HEADER * m_pSectionHeader = ( IMAGE_SECTION_HEADER * )
	//	( ( ( ULONG_PTR ) &ntHeaders->OptionalHeader ) + ntHeaders->FileHeader.SizeOfOptionalHeader );

	//
	//

	///*REMOVE DEBUG SYMBOLS */

	//PIMAGE_DEBUG_DIRECTORY* p_debug; size_t debug_size;

	//p_debug = ( PIMAGE_DEBUG_DIRECTORY * ) GetPtrFromRVA (
	//	( DWORD ) ( ntHeaders->OptionalHeader.DataDirectory [ IMAGE_DIRECTORY_ENTRY_BASERELOC ].VirtualAddress ),
	//	ntHeaders,
	//	( uint8_t * ) pe_rawf.data ( ) );

	//debug_size = ntHeaders->OptionalHeader.DataDirectory [ IMAGE_DIRECTORY_ENTRY_BASERELOC ].Size;
	//
	//// Zero it.
	//if ( p_debug ) ZeroMemory ( p_debug, debug_size );

	//ntHeaders->OptionalHeader.DataDirectory [ IMAGE_DIRECTORY_ENTRY_DEBUG ] = { 0, 0 };

	//// Strip it.
	//ntHeaders->FileHeader.NumberOfSymbols = 0;
	//ntHeaders->FileHeader.PointerToSymbolTable = 0;

	//// Configure the sections.
	//PIMAGE_SECTION_HEADER c_sec = ( PIMAGE_SECTION_HEADER ) &pe_rawf.data ( ) [ dosHeaders->e_lfanew +
	//	sizeof ( ntHeaders->Signature ) + sizeof ( ntHeaders->FileHeader ) +
	//	ntHeaders->FileHeader.SizeOfOptionalHeader ];
	//for ( size_t idx = 0; idx < ntHeaders->FileHeader.NumberOfSections; idx++ ) {
	//	// Strip all of the information.
	//	c_sec [ idx ].PointerToLinenumbers = 0;
	//	c_sec [ idx ].NumberOfLinenumbers = 0;
	//};
	//


	///* Remove relocation */
	//
	//LIMAGE_BASE_RELOCATION * p_relocs; size_t relocs_size = ntHeaders->OptionalHeader.DataDirectory [ IMAGE_DIRECTORY_ENTRY_BASERELOC ].Size;

	//p_relocs = ( LIMAGE_BASE_RELOCATION * ) GetPtrFromRVA (
	//	( DWORD ) ( ntHeaders->OptionalHeader.DataDirectory [ IMAGE_DIRECTORY_ENTRY_BASERELOC ].VirtualAddress ),
	//	ntHeaders,
	//	( uint8_t * ) pe_rawf.data ( ) );

	///* */
	//if ( p_relocs ) ZeroMemory ( p_relocs, relocs_size );
	//ntHeaders->OptionalHeader.DataDirectory [ IMAGE_DIRECTORY_ENTRY_BASERELOC ] = { 0, 0 };

	//// Stop the relocations.
	//ntHeaders->FileHeader.Characteristics |= IMAGE_FILE_RELOCS_STRIPPED;

	//ntHeaders->FileHeader.NumberOfSections = 99;

	//ntHeaders->OptionalHeader.AddressOfEntryPoint = 0x0;

	///*Remove .rsrcs*/
	//IMAGE_DATA_DIRECTORY * resource; size_t resource_size;

	//resource = ( IMAGE_DATA_DIRECTORY * ) GetPtrFromRVA (
	//	( DWORD ) ( ntHeaders->OptionalHeader.DataDirectory [ IMAGE_DIRECTORY_ENTRY_RESOURCE ].VirtualAddress ),
	//	ntHeaders,
	//	( uint8_t * ) pe_rawf.data ( ) );

	//resource_size = ntHeaders->OptionalHeader.DataDirectory [ IMAGE_DIRECTORY_ENTRY_RESOURCE ].Size;

	//// Zero it.
	//if ( p_debug ) ZeroMemory ( p_debug, debug_size );

	/*erase and corrupt header*/
	//for ( size_t i = 0; i < 260; i++ ) {
	//	if ( i < msg.size ( ) )
	//		 pe_rawf.at(i) = msg.at ( i );
	//	else
	//		pe_rawf.at ( i ) = 0x0;
	//}

	std::cout << "Writing file dump." << std::endl;

	auto myfile = std::fstream ( "dlldump.dll", std::ios::out | std::ios::binary );
	myfile.write ( (char*)pe_rawf.data(), dllImageSize );
	myfile.close ( );

	std::cout << "Written file dump." << std::endl;
	//unsigned int nBytes;
	MapSections ( GetCurrentProcess ( ), dllBase, pe_rawf.data(), ntHeaders );



	//WipePEGarbage ((uintptr_t) dllBase );

	static auto pattern_to_byte = [ ] ( const char * pattern ) {
		auto bytes = std::vector<int> {};
		auto start = const_cast< char * >( pattern );
		auto end = const_cast< char * >( pattern ) + std::strlen ( pattern );

		for ( auto current = start; current < end; ++current ) {
			if ( *current == '?' ) {
				++current;

				if ( *current == '?' )
					++current;

				bytes.push_back ( -1 );
			}
			else {
				bytes.push_back ( std::strtoul ( current, &current, 16 ) );
			}
		}
		return bytes;
	};

	
	std::uint8_t address_found;

	auto size_of_image = ntHeaders->OptionalHeader.SizeOfImage;
	std::cout << "size_of_image " << size_of_image << std::endl <<std::endl;
	auto pattern_bytes = pattern_to_byte ( "8D 4D E4 E8 ? ? ? ? 50" );
	auto scan_bytes = reinterpret_cast< std::uint8_t * >( dllBase );

	auto s = pattern_bytes.size ( );
	auto d = pattern_bytes.data ( );
	using DLLEntry = BOOL ( WINAPI * )( HINSTANCE dll, DWORD reason, LPVOID reserved );

	for ( auto i = 0ul; i < size_of_image - s; ++i ) {
		bool found = true;

		for ( auto j = 0ul; j < s; ++j ) {
			if ( scan_bytes [ i + j ] != d [ j ] && d [ j ] != -1 ) {
				found = false;
				break;
			}
		}
		if ( found ) {
			std::cout << "Found function mamaluinike " << &scan_bytes [ i ] << std::endl;
			std::cout << "data " << ( const char * ) ( &scan_bytes [ i ] );

		

			////

			//DLLEntry DllEntry = ( DLLEntry ) ( &scan_bytes [ i ] );
			//( *DllEntry )( ( HINSTANCE ) dllBase, DLL_PROCESS_ATTACH, ( void * ) ntHeaders->OptionalHeader.SizeOfImage );

			//address_found = scan_bytes [ i ];
		}
	}



	
	//dataReady = true;
	return 0;
}


bool Hook32(char* src, char* dst, const intptr_t len)
{
	if (len < 5) return false;

	DWORD  curProtection;
	VirtualProtect(src, len, PAGE_EXECUTE_READWRITE, &curProtection);

	intptr_t  relativeAddress = (intptr_t)(dst - (intptr_t)src) - 5;

	*src = (char)'\xE9';
	*(intptr_t*)((intptr_t)src + 1) = relativeAddress;

	VirtualProtect(src, len, curProtection, &curProtection);
	return true;
}

char* TrampHook32(char* src, char* dst, const intptr_t len)
{
	// Make sure the length is greater than 5
	if (len < 5) return 0;

	// Create the gateway (len + 5 for the overwritten bytes + the jmp)
	void* gateway = VirtualAlloc(0, len + 5, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	//Write the stolen bytes into the gateway
	memcpy(gateway, src, len);

	// Get the gateway to destination addy
	intptr_t  gatewayRelativeAddr = ((intptr_t)src - (intptr_t)gateway) - 5;

	// Add the jmp opcode to the end of the gateway
	*(char*)((intptr_t)gateway + len) = 0xE9; //truncation? 0xe9

	// Add the address to the jmp
	*(intptr_t*)((intptr_t)gateway + len + 1) = gatewayRelativeAddr;

	// Place the hook at the destination
	Hook32(src, dst, len);

	return (char*)gateway;
}


using PrototypeWriteProcessMemory = int (WINAPI*)(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten);

// remember memory address of the original MessageBoxA routine
PrototypeWriteProcessMemory originalMsgBox = WriteProcessMemory;

// hooked function with malicious code that eventually calls the original MessageBoxA
int WriteProcessMemoryHK(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten)
{
	//	MessageBoxW(NULL, L"Ola Hooked from a Rogue Senor .o.", L"Ola Senor o/", 0);

	std::cout << "A folosit prostu writeprocessmemory " << std::endl;
	std::cout << "lpBaseAddress " << lpBaseAddress <<  " size " << nSize << std::endl;
	
	// execute the original NessageBoxA
	return 1;// originalMsgBox(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
}

void** IATfind(const char* function, HMODULE modules) {
	int ip = 0;


	PIMAGE_DOS_HEADER pImgDosHeaders = (PIMAGE_DOS_HEADER)modules;
	PIMAGE_NT_HEADERS pImgNTHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)pImgDosHeaders + pImgDosHeaders->e_lfanew);
	PIMAGE_IMPORT_DESCRIPTOR pImgImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)pImgDosHeaders + pImgNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	int size = (int)((LPBYTE)pImgDosHeaders + pImgNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size);

	if (pImgDosHeaders->e_magic != IMAGE_DOS_SIGNATURE)
		printf("e_magic is no valid DOS signature\n");

	for (IMAGE_IMPORT_DESCRIPTOR* iid = pImgImportDesc; iid->Name != NULL; iid++) {
		for (int funcIdx = 0; *(funcIdx + (LPVOID*)(iid->FirstThunk + (SIZE_T)modules)) != NULL; funcIdx++) {
			char* modFuncName = (char*)(*(funcIdx + (SIZE_T*)(iid->OriginalFirstThunk + (SIZE_T)modules)) + (SIZE_T)modules + 2);
			//	std::cout << "modFuncName " << modFuncName << std::endl;
			if (!_stricmp(function, modFuncName))
				return funcIdx + (LPVOID*)(iid->FirstThunk + (SIZE_T)modules);
		}
	}
	return 0;
}

unsigned long WINAPI initclaudelu(void* instance) {

	//MessageBoxA(NULL, "Hello Before Hooking", "Hello Before Hooking", 0);

	auto kernel32Base = GetModuleHandleA(NULL);

	DWORD oldrights, newrights = PAGE_READWRITE;
	auto funcptr = IATfind("WriteProcessMemory", kernel32Base);

	std::cout << "Messagebox Address " << funcptr << std::endl;


	bool resprotect = VirtualProtect(funcptr, sizeof(LPVOID), newrights, &oldrights);
	std::cout << "resprotect " << resprotect << std::endl;

	void** old = funcptr;
	*funcptr = &WriteProcessMemoryHK;
	VirtualProtect(funcptr, sizeof(LPVOID), oldrights, &newrights);


	while (true) {
		std::cout << "_";
	}
	//MessageBoxA(NULL, "Hello after Hooking", "Hello after Hooking", 0);
	//*funcptr = *old;
	return 0;
}

std::int32_t WINAPI DllMain ( const HMODULE instance [[maybe_unused]], const unsigned long reason, const void * reserved [[maybe_unused]] ) {
	DisableThreadLibraryCalls ( instance );

	switch ( reason ) {

	case DLL_PROCESS_ATTACH:
	{

		std::cout << "DLL_PROCESS_ATTACH " << std::endl;
		if ( auto handle = CreateThread ( nullptr, NULL, initclaudelu, instance, NULL, nullptr ) )
			CloseHandle ( handle );

		//if ( auto handle = CreateThread ( nullptr, NULL, initialize, instance, NULL, nullptr ) )
		//	CloseHandle ( handle );
		


		
		
		break;
	}

	case DLL_PROCESS_DETACH:
	{
	
		break;
	}
	}

	return true;
}



