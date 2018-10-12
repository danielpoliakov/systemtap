// -*- C++ -*-
// Copyright (C) 2017-2018 Red Hat Inc.
//
// This file is part of systemtap, and is free software.  You can
// redistribute it and/or modify it under the terms of the GNU General
// Public License (GPL); either version 2, or (at your option) any
// later version.

#ifndef CSINFO_H
#define CSINFO_H

#if HAVE_NSS

#include "session.h"
#include "csclient.h"
#include "cscommon.h"
#include <string>
#include <vector>
#include <ostream>

/* Exit error codes */
#define NSS_SUCCESS                   0
#define NSS_GENERAL_ERROR             1
#define NSS_CA_CERT_INVALID_ERROR     2
#define NSS_SERVER_CERT_EXPIRED_ERROR 3

// Utility functions
void nss_client_query_server_status (systemtap_session &s);
void nss_client_manage_server_trust (systemtap_session &s);

SECStatus nss_trustNewServer (CERTCertificate *serverCert);

// Information about compile servers.
struct compile_server_info
{
  compile_server_info ();

  std::string host_name;
  std::string unresolved_host_name;
  PRNetAddr address;
  unsigned short port;
  bool fully_specified;
  std::string version;
  std::string sysinfo;
  std::string certinfo;
  std::vector<std::string> mok_fingerprints;

  bool empty () const;
  bool hasAddress () const;
  unsigned short setAddressPort (unsigned short port);
  bool isComplete () const;
  std::string host_specification () const;

  bool operator== (const compile_server_info &that) const;

  // Used to sort servers by preference for order of contact. The
  // preferred server is "less" than the other one.
  bool operator< (const compile_server_info &that) const;
};

std::ostream &operator<< (std::ostream &s, const compile_server_info &i);
std::ostream &operator<< (std::ostream &s,
			  const std::vector<compile_server_info> &v);


std::string global_client_cert_db_path ();

std::string signing_cert_db_path ();

void get_server_info_from_db (systemtap_session &s,
			 std::vector<compile_server_info> &servers,
			 const std::string &cert_db_path);


void
nss_get_all_server_info (systemtap_session &s,
			 std::vector<compile_server_info> &servers);
void
nss_get_specified_server_info (systemtap_session &s,
			       std::vector<compile_server_info> &servers,
			       bool no_default = false);

void
nss_get_or_keep_online_server_info (systemtap_session &s,
				    std::vector<compile_server_info> &servers,
				    bool keep);
void
nss_get_or_keep_trusted_server_info (systemtap_session &s,
				     std::vector<compile_server_info> &servers,
				     bool keep);
void
nss_get_or_keep_signing_server_info (systemtap_session &s,
				     std::vector<compile_server_info> &servers,
				     bool keep);
void
nss_get_or_keep_compatible_server_info (systemtap_session &s,
					std::vector<compile_server_info> &servers,
					bool keep);
void
nss_keep_common_server_info (const compile_server_info &info_to_keep,
			     std::vector<compile_server_info> &filtered_info);
void
nss_keep_common_server_info (const std::vector<compile_server_info> &info_to_keep,
			     std::vector<compile_server_info> &filtered_info);
void
nss_keep_server_info_with_cert_and_port (systemtap_session &s,
					 const compile_server_info &server,
					 std::vector<compile_server_info> &servers);

void
nss_add_server_info (const compile_server_info &info,
		     std::vector<compile_server_info> &list);
void
nss_add_server_info (const std::vector<compile_server_info> &source,
		     std::vector<compile_server_info> &target);

void
nss_add_online_server_info (systemtap_session &s,
			    const compile_server_info &info);
#endif	// HAVE_NSS

#endif	// CSINFO_H
