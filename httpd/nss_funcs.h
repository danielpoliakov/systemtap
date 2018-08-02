// systemtap compile-server web api NSS functions header
// Copyright (C) 2018 Red Hat Inc.
//
// This file is part of systemtap, and is free software.  You can
// redistribute it and/or modify it under the terms of the GNU General
// Public License (GPL); either version 2, or (at your option) any
// later version.

#ifndef __NSS_H__
#define __NSS_H__

#include <string>

extern int nss_init(std::string &cert_db_path);
extern void nss_get_server_cert_info(std::string &cert_serial, std::string &cert_pem);
extern bool nss_get_server_pw_info (const std::string &db_path, const std::string &nss_cert_name,
    std::string &key, std::string &cert);
extern void nss_shutdown(std::string &cert_db_path);

#endif	/* __NSS_H__ */
