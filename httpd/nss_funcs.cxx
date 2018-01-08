// systemtap compile-server web api server NSS functions
// Copyright (C) 2018 Red Hat Inc.
//
// This file is part of systemtap, and is free software.  You can
// redistribute it and/or modify it under the terms of the GNU General
// Public License (GPL); either version 2, or (at your option) any
// later version.

#include "../nsscommon.h"
#include "nss_funcs.h"
#include <iostream>

extern "C" {
#include <prinit.h>
}

using namespace std;

// Called from methods within nsscommon.cxx.
extern "C"
void
nsscommon_error(const char *msg, int logit __attribute ((unused)))
{
  clog << msg << endl;
}

int
nss_init(string &cert_db_path)
{
    // Where is the ssl certificate/key database?
    if (cert_db_path.empty())
	cert_db_path = server_cert_db_path();
    const char *nickName = server_cert_nickname();
    if (check_cert(cert_db_path, nickName) != 0)
	return 1;

    /* Call the NSPR (Netscape Portable Runtime) initialization
     * routines. Note that the arguments are really ignored. */
    PR_Init(PR_SYSTEM_THREAD, PR_PRIORITY_NORMAL, 1);

    /* Set the cert database password callback. */
    PK11_SetPasswordFunc(nssPasswordCallback);

    /* Initialize NSS. */
    SECStatus secStatus = nssInit(cert_db_path.c_str());
    if (secStatus != SECSuccess) {
	// Message already issued.
	return 1;
    }

    return 0;
}

void
nss_shutdown(string &cert_db_path)
{
    /* Shutdown NSS and exit NSPR gracefully. */
    nssCleanup(cert_db_path.c_str());
    PR_Cleanup();
}
