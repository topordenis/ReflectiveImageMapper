#include "inc.h"


namespace ssl_manager {
    /// Verify that one of the subject alternative names matches the given hostname
    //bool verify_subject_alternative_name ( const char * hostname, X509 * cert ) {
    //    STACK_OF ( GENERAL_NAME ) * san_names = NULL;

    //    san_names = ( STACK_OF ( GENERAL_NAME ) * ) X509_get_ext_d2i ( cert, NID_subject_alt_name, NULL, NULL );
    //    if ( san_names == NULL ) {
    //        return false;
    //    }

    //    int san_names_count = sk_GENERAL_NAME_num ( san_names );

    //    bool result = false;

    //    for ( int i = 0; i < san_names_count; i++ ) {
    //        const GENERAL_NAME * current_name = sk_GENERAL_NAME_value ( san_names, i );

    //        if ( current_name->type != GEN_DNS ) {
    //            continue;
    //        }

    //        char const * dns_name = ( char const * ) ASN1_STRING_get0_data ( current_name->d.dNSName );

    //        // Make sure there isn't an embedded NUL character in the DNS name
    //        if ( ASN1_STRING_length ( current_name->d.dNSName ) != strlen ( dns_name ) ) {
    //            break;
    //        }
    //        // Compare expected hostname with the CN
    //        result = ( strcmp ( hostname, dns_name ) == 0 );
    //    }
    //    sk_GENERAL_NAME_pop_free ( san_names, GENERAL_NAME_free );

    //    return result;
    //}

    /// Verify that the certificate common name matches the given hostname
    //bool verify_common_name ( char const * hostname, X509 * cert ) {
    //    // Find the position of the CN field in the Subject field of the certificate
    //    int common_name_loc = X509_NAME_get_index_by_NID ( X509_get_subject_name ( cert ), NID_commonName, -1 );
    //    if ( common_name_loc < 0 ) {
    //        return false;
    //    }

    //    // Extract the CN field
    //    X509_NAME_ENTRY * common_name_entry = X509_NAME_get_entry ( X509_get_subject_name ( cert ), common_name_loc );
    //    if ( common_name_entry == NULL ) {
    //        return false;
    //    }

    //    // Convert the CN field to a C string
    //    ASN1_STRING * common_name_asn1 = X509_NAME_ENTRY_get_data ( common_name_entry );
    //    if ( common_name_asn1 == NULL ) {
    //        return false;
    //    }

    //    char const * common_name_str = ( char const * ) ASN1_STRING_get0_data ( common_name_asn1 );

    //    // Make sure there isn't an embedded NUL character in the CN
    //    if ( ASN1_STRING_length ( common_name_asn1 ) != strlen ( common_name_str ) ) {
    //        return false;
    //    }

    //    // Compare expected hostname with the CN
    //    return ( strcmp ( hostname, common_name_str ) == 0 );
    //}

    /**
     * This code is derived from examples and documentation found ato00po
     * http://www.boost.org/doc/libs/1_61_0/doc/html/boost_asio/example/cpp03/ssl/client.cpp
     * and
     * https://github.com/iSECPartners/ssl-conservatory
     */
    //bool verify_certificate ( const char * hostname, bool preverified, boost::asio::ssl::verify_context & ctx ) {
    //    // The verify callback can be used to check whether the certificate that is
    //    // being presented is valid for the peer. For example, RFC 2818 describes
    //    // the steps involved in doing this for HTTPS. Consult the OpenSSL
    //    // documentation for more details. Note that the callback is called once
    //    // for each certificate in the certificate chain, starting from the root
    //    // certificate authority.

    //    // Retrieve the depth of the current cert in the chain. 0 indicates the
    //    // actual server cert, upon which we will perform extra validation
    //    // (specifically, ensuring that the hostname matches. For other certs we
    //    // will use the 'preverified' flag from Asio, which incorporates a number of
    //    // non-implementation specific OpenSSL checking, such as the formatting of
    //    // certs and the trusted status based on the CA certs we imported earlier.
    //    int depth = X509_STORE_CTX_get_error_depth ( ctx.native_handle ( ) );

    //    // if we are on the final cert and everything else checks out, ensure that
    //    // the hostname is present on the list of SANs or the common name (CN).
    //    if ( depth == 0 && preverified ) {
    //        X509 * cert = X509_STORE_CTX_get_current_cert ( ctx.native_handle ( ) );

    //        if ( verify_subject_alternative_name ( hostname, cert ) ) {
    //            return true;
    //        }
    //        else if ( verify_common_name ( hostname, cert ) ) {
    //            return true;
    //        }
    //        else {
    //            return false;
    //        }
    //    }

    //    return preverified;
    //}
};