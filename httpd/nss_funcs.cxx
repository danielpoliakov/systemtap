// systemtap compile-server web api server NSS functions
// Copyright (C) 2018 Red Hat Inc.
//
// This file is part of systemtap, and is free software.  You can
// redistribute it and/or modify it under the terms of the GNU General
// Public License (GPL); either version 2, or (at your option) any
// later version.

#include "../nsscommon.h"
#include "../cscommon.h"
#include "nss_funcs.h"
#include <iostream>
#include "utils.h"

extern "C" {
#include <prinit.h>
}

using namespace std;

// Called from methods within nsscommon.cxx.
extern "C"
void
nsscommon_error(const char *msg, int logit __attribute ((unused)))
{
    server_error(msg);
}

static string
server_cert_file()
{
    return server_cert_db_path() + "/stap.cert";
}

int
nss_init(string &cert_db_path)
{
    // Where is the ssl certificate/key database?
    if (cert_db_path.empty())
	cert_db_path = server_cert_db_path();
    const char *nickName = server_cert_nickname();

    // Ensure that our certificate is valid. Generate a new one if not.
    if (check_cert(cert_db_path, nickName) != 0) {
	// Message already issued.
	return 1;
    }

    // Ensure that our certificate is trusted by our local client.
    // Construct the client database path relative to the server
    // database path.
    SECStatus secStatus = add_client_cert(server_cert_file(),
					  local_client_cert_db_path());
    if (secStatus != SECSuccess) {
	// Not fatal. Other clients may trust the server and trust can
	// be added for the local client in other ways.
	server_error(_("Unable to authorize certificate for the local client"));
    }

    /* Call the NSPR (Netscape Portable Runtime) initialization
     * routines. Note that the arguments are really ignored. */
    PR_Init(PR_SYSTEM_THREAD, PR_PRIORITY_NORMAL, 1);

    /* Set the cert database password callback. */
    PK11_SetPasswordFunc(nssPasswordCallback);

    /* Initialize NSS. */
    secStatus = nssInit(cert_db_path.c_str());
    if (secStatus != SECSuccess) {
	// Message already issued.
	return 1;
    }

    return 0;
}

string
nss_get_server_cert_info()
{
    CERTCertificate *cert = PK11_FindCertFromNickname (server_cert_nickname (),
						       NULL);
    string cert_info;
    if (cert == NULL) {
	server_error (_("Unable to find our certificate in the database"));
	nssError ();
    }
    else {
	// Get the certificate serial number
	cert_info = get_cert_serial_number(cert);

	// We're done with the certificate.
	CERT_DestroyCertificate(cert);
    }
    return cert_info;
}

void
nss_shutdown(string &cert_db_path)
{
    /* Shutdown NSS and exit NSPR gracefully. */
    nssCleanup(cert_db_path.c_str());
    PR_Cleanup();
}
