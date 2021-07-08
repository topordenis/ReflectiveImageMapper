#include  <vector>
#include "Utils.h"
#include <chrono>
#include <complex>

#include <Windows.h>
#include <iostream>

namespace Utils
{
    void CreateConsole ( ) {

        if ( !AllocConsole ( ) ) {
            // Add some error handling here.
            // You can call GetLastError() to get more info about the error.
            return;
        }

        // std::cout, std::clog, std::cerr, std::cin
        FILE * fDummy;
        freopen_s ( &fDummy, "CONOUT$", "w", stdout );
        freopen_s ( &fDummy, "CONOUT$", "w", stderr );
        freopen_s ( &fDummy, "CONIN$", "r", stdin );
        std::cout.clear ( );
        std::clog.clear ( );
        std::cerr.clear ( );
        std::cin.clear ( );

        // std::wcout, std::wclog, std::wcerr, std::wcin
        HANDLE hConOut = CreateFile (  ( "CONOUT$" ), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL );
        HANDLE hConIn = CreateFile (  ( "CONIN$" ), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL );
        SetStdHandle ( STD_OUTPUT_HANDLE, hConOut );
        SetStdHandle ( STD_ERROR_HANDLE, hConOut );
        SetStdHandle ( STD_INPUT_HANDLE, hConIn );
        std::wcout.clear ( );
        std::wclog.clear ( );
        std::wcerr.clear ( );
        std::wcin.clear ( );
    }
    void ReleaseConsole ( ) {
        fclose ( ( _iobuf * ) __acrt_iob_func ( 0 ) );
        fclose ( ( _iobuf * ) __acrt_iob_func ( 1 ) );
        fclose ( ( _iobuf * ) __acrt_iob_func ( 2 ) );

        FreeConsole ( );
    }

    std::vector<unsigned char> OTPKey ( int ping ) {
   
        std::vector<unsigned char> key { 10, 137, 237, 232, 4, 198, 81, 206 ,109, 152, 158, 30 ,78, 193, 13, 114

        };
        return key;
        int delay = ( ping * 2 ) * 8;
        const auto p1 = std::chrono::system_clock::now ( );

        auto minute = std::chrono::duration_cast< std::chrono::minutes >(
            p1.time_since_epoch ( ) ).count ( );

        auto miliseconds = std::chrono::duration_cast< std::chrono::milliseconds >(
            p1.time_since_epoch ( ) ).count ( );


        int end = ( miliseconds / delay ) % 10;
        int end_minute = ( minute % 10 );
        if ( end_minute == 0 )
            end_minute = 1;

        int pow = (int)std::pow ( end, end_minute );

        if ( pow == 0 ) {
            pow = 53;
        }

        pow *= std::chrono::duration_cast< std::chrono::minutes >( p1.time_since_epoch ( ) ).count ( ) / delay;

        pow = std::abs ( pow );


        for ( int i = 0; i < 16; i++ )

            key.push_back ( ( char ) ( pow % ( i * i + ( i + 1 ) ) ) );

        return key;

    }


}