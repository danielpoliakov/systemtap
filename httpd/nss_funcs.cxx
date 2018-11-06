// systemtap compile-server web api server NSS functions
// Copyright (C) 2018 Red Hat Inc.
//
// This file is part of systemtap, and is free software.  You can
// redistribute it and/or modify it under the terms of the GNU General
// Public License (GPL); either version 2, or (at your option) any
// later version.

#include "../nsscommon.h"
#include "../cscommon.h"
#include "../util.h"
#include "nss_funcs.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include "utils.h"

extern "C" {
#include <sys/stat.h>
#include <prinit.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
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
					  local_client_cert_db_path(), db_nssinit);
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

void
nss_get_server_cert_info(string &cert_serial, string &cert_pem)
{
    CERTCertificate *cert = PK11_FindCertFromNickname (server_cert_nickname (),
						       NULL);
    if (cert == NULL) {
	server_error (_("Unable to find our certificate in the database"));
	nssError ();
    }
    else {
	// Get the certificate serial number
	cert_serial = get_cert_serial_number(cert);
	if (cvt_nss_to_pem (cert, cert_pem) == false) {
	    server_error (_("Unable to find our certificate in the database"));
	    nssError ();
	}


	// We're done with the certificate.
	CERT_DestroyCertificate(cert);
    }

}

void
nss_shutdown(string &cert_db_path)
{
  /* Shutdown NSS and exit NSPR gracefully. */
  nssCleanup(cert_db_path.c_str(), NULL);
  PR_Cleanup();
}


bool
nss_get_server_pw_info (const string &db_path, const string &nss_cert_name,
    string &key, string &cert)
{
  CERTCertificate *c;
  BIO *bio;
  X509 *certificate_509;

  // Get the certificate from the nss certificate database
  c = PK11_FindCertFromNickname (server_cert_nickname (), NULL);
  // TODO Use cvt_nss_to_pem (
  bio = BIO_new(BIO_s_mem());
  certificate_509 = X509_new();

  // Load the nss certificate into the openssl BIO
  int count = BIO_write (bio, (const void*)c->derCert.data, c->derCert.len);
  if (count == 0)
    nsscommon_error (_("BIO_write failed"));
  // Parse the BIO into an X509
  certificate_509 = d2i_X509_bio(bio, &certificate_509);
  // Convert the X509 to PEM form
  int rc = PEM_write_bio_X509(bio, certificate_509);
  if (rc != 1)
    nsscommon_error (_("PEM_write_bio_X509 failed"));
  BUF_MEM *mem = NULL;
  // Load the buffer from the PEM form
  BIO_get_mem_ptr(bio, &mem);
  string pem(mem->data, mem->length);
  BIO_free(bio);
  X509_free(certificate_509);

  // We have the certificate; now get the corresponding private key
  // in pem form by invoking pk12util followed by openssl pkcs12
  string pk12_tmp = "/tmp/pk12utilXXXXXX";
  int fd = mkstemp ((char*)pk12_tmp.c_str());
  close(fd);
  if (fd == -1)
    return false;

  vector<string> pk12util {"pk12util", "-o", pk12_tmp, "-n", nss_cert_name,
    "-K", "", "-W", "", "-d", db_path};
  int pid = stap_spawn (2, pk12util);
  stap_waitpid (2, pid);

  string pem_tmp = "/tmp/pemXXXXXX";
  fd = mkstemp ((char*)pem_tmp.c_str());
  close(fd);
  if (fd == -1)
    return false;
  chmod (pem_tmp.c_str(), (unsigned int)(S_IRUSR | S_IWUSR));

  vector<string> openssl {"openssl", "pkcs12", "-in", pk12_tmp, "-out", pem_tmp,
    "-nodes", "-clcerts", "-password", "pass:"};
  pid = stap_spawn (2, openssl);
  stap_waitpid (2, pid);
  remove_file_or_dir (pk12_tmp.c_str());

  // pem_tmp is a pem file containing the server certificate and private key
  // a pem file X.509 certificate encoded using DER then encoeded using Base64
  // with plain-text anchor lines.

  std::ifstream ifs(pem_tmp);
  std::string pems;
  pems.assign((std::istreambuf_iterator<char>(ifs) ),
              (std::istreambuf_iterator<char>()));

  remove_file_or_dir (pem_tmp.c_str());

  // Ensure that the original nss certificate matches one of the pem certificates
  size_t cursor = 0;
  size_t priv_begin, priv_end, cert_begin, cert_end;
  string pem_certificate;
  string priv_key;
  while (cursor < pems.size())
    {
      if ((priv_begin = pems.find("-----BEGIN PRIVATE KEY-----", cursor)) == string::npos)
        return false;
      if ((priv_end = pems.find("-----END PRIVATE KEY-----", priv_begin)) == string::npos)
        return false;
      if ((cert_begin = pems.find("-----BEGIN CERTIFICATE-----", priv_end)) == string::npos)
        return false;
      if ((cert_end = pems.find("-----END CERTIFICATE-----", cert_begin)) == string::npos)
        return false;
      priv_key = pems.substr(priv_begin, priv_end - priv_begin + 26);
      pem_certificate = pems.substr(cert_begin, cert_end - cert_begin + 28);

      if (pem == pem_certificate)
        {
          // Found a match so use its private key
          key = priv_key;
          CERT_DestroyCertificate (c);
          cert = pem;
          return true;
        }
      else
        cursor = cert_end;
    }

  return false;
}
