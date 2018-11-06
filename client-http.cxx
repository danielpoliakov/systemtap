// -*- C++ -*-
// Copyright (C) 2017, 2018 Red Hat Inc.
//
// This file is part of systemtap, and is free software.  You can
// redistribute it and/or modify it under the terms of the GNU General
// Public License (GPL); either version 2, or (at your option) any
// later version.

#include "config.h"

#ifdef HAVE_HTTP_SUPPORT
#include "session.h"
#include "client-http.h"
#include "util.h"
#include "staptree.h"
#include "elaborate.h"
#include "nsscommon.h"

#include <iostream>
#include <sstream>
#include <fstream>
#include <map>
#include <vector>


extern "C" {
#include <string.h>
#include <curl/curl.h>
#include <curl/easy.h>
#include <json-c/json.h>
#include <sys/stat.h>
#include <rpm/rpmlib.h>
#include <rpm/header.h>
#include <rpm/rpmts.h>
#include <rpm/rpmdb.h>
#include <search.h>
#include <elfutils/libdwfl.h>
#include <elfutils/libdw.h>
#include <fcntl.h>
#include <nss3/nss.h>
}

using namespace std;


class http_client
{
public:
  http_client (systemtap_session &s):
    root(0),
    s(s),
    curl(0),
    retry(0),
    location(nullptr) { }
  ~http_client () {if (curl) curl_easy_cleanup(curl);
                   remove_file_or_dir (pem_cert_file.c_str());}

  json_object *root;
  std::map<std::string, std::string> header_values;
  std::vector<std::tuple<std::string, std::string>> env_vars;
  enum download_type {json_type, file_type};
  std::string pem_cert_file;
  std::string host;
  enum cert_type {signer_trust, ssl_trust};


  bool download (const std::string & url, enum download_type type, bool report_errors, bool cleanup);
  bool download_pem_cert (const std::string & url, std::string & certs);
  bool post (const string & url, vector<tuple<string, string>> & request_parameters);
  void add_file (std::string filename);
  void add_module (std::string module);
  void get_header_field (const std::string & data, const std::string & field);
  static size_t get_data_shim (void *ptr, size_t size, size_t nitems, void *client);
  static size_t get_file (void *ptr, size_t size, size_t nitems, FILE * stream);
  static size_t get_header_shim (void *ptr, size_t size, size_t nitems, void *client);
  std::string get_rpmname (std::string & pathname);
  void get_buildid (string fname);
  void get_kernel_buildid (void);
  long get_response_code (void);
  bool add_server_cert_to_client (std::string & tmpdir, db_init_types db_init_type);
  static int trace (CURL *, curl_infotype type, unsigned char *data, size_t size, void *);
  bool delete_op (const std::string & url);
  bool check_trust (enum cert_type, vector<compile_server_info> &specified_servers);

private:
  size_t get_header (void *ptr, size_t size, size_t nitems);
  size_t get_data (void *ptr, size_t size, size_t nitems);
  static int process_buildid_shim (Dwfl_Module *dwflmod, void **userdata, const char *name,
      Dwarf_Addr base, void *client);
  int process_buildid (Dwfl_Module *dwflmod);
  std::vector<std::string> files;
  std::vector<std::string> modules;
  std::vector<std::tuple<std::string, std::string>> buildids;
  systemtap_session &s;
  CURL *curl;
  int retry;
  std::string *location;
  std::string buildid;
};

// TODO is there a better way than making this static?
static http_client *http;


size_t
http_client::get_data_shim (void *ptr, size_t size, size_t nitems, void *client)
{
  http_client *http = static_cast<http_client *>(client);

  return http->get_data (ptr, size, nitems);
}

// Parse the json data at PTR having SIZE and NITEMS into root

size_t
http_client::get_data (void *ptr, size_t size, size_t nitems)
{
  string data ((const char *) ptr, (size_t) size * nitems);

  // Process the JSON data.
  if (data.front () == '{')
    {
      enum json_tokener_error json_error;
      root = json_tokener_parse_verbose (data.c_str(), &json_error);

      if (root == NULL)
        throw SEMANTIC_ERROR (json_tokener_error_desc (json_error));
    }
  else
    {
      clog << "Malformed JSON data: '" << data << "'" << endl;
    }
  return size * nitems;
}


size_t
http_client::get_header_shim (void *ptr, size_t size, size_t nitems, void *client)
{
  http_client *http = static_cast<http_client *>(client);

  return http->get_header (ptr, size, nitems);
}


// Extract header values at PTR having SIZE and NITEMS into header_values

size_t
http_client::get_header (void *ptr, size_t size, size_t nitems)
{
  string data ((const char *) ptr, (size_t) size * nitems);

  unsigned long colon = data.find(':');
  if (colon != string::npos)
    {
      string key = data.substr (0, colon);
      string value = data.substr (colon + 2, data.length() - colon - 4);
      header_values[key] = value;
    }

  return size * nitems;
}


// Put the  data, e.g. <module>.ko at PTR having SIZE and NITEMS into STREAM

size_t
http_client::get_file (void *ptr, size_t size, size_t nitems, std::FILE * stream)
{
  size_t written;
  written = fwrite (ptr, size, nitems, stream);
  std::fflush (stream);
  return written;
}


// Trace sent and received packets

int
http_client::trace(CURL *, curl_infotype type, unsigned char *data, size_t size, void *)
{
  string text;

  switch(type)
  {
  case CURLINFO_TEXT:
    clog << "== Info: " << data;
    return 0;

  case CURLINFO_HEADER_OUT:
    text = "=> Send header";
    break;
  case CURLINFO_DATA_OUT:
    text = "=> Send data";
    break;
  case CURLINFO_HEADER_IN:
    text = "<= Recv header";
    break;
  case CURLINFO_DATA_IN:
    text = "<= Recv data";
    break;
  default:
    return 0;
  }

  size_t i;
  size_t c;

  const unsigned int width = 64;
  // Packet contents exceeding this size are probably downloaded file components
  const unsigned int max_size = 0x2000;

  clog << text << " " << size << " bytes (" << showbase << hex << size << ")" << dec << noshowbase << endl;

   if (size > max_size)
     return 0;

  for (i = 0; i < size; i += width)
    {
      clog << setw(4) << setfill('0') << hex << i << dec << setfill(' ') << ": ";

      for (c = 0; (c < width) && (i + c < size); c++)
        {
          if ((i + c + 1 < size) && data[i + c] == '\r' && data[i + c + 1] == '\n')
            {
              i += (c + 2 - width);
              break;
            }

          clog << (char)(isprint (data[i + c]) ? data[i + c] : '.');
          if ((i + c + 2 < size) && data[i + c + 1] == '\r' && data[i + c + 2] == '\n')
            {
              i += (c + 3 - width);
              break;
            }
        }
      clog << endl;
    }

  return 0;
}


// Read the certificate bundle corresponding to 'url into 'certs'

bool
http_client::download_pem_cert (const std::string & url, string & certs)
{
  CURL *dpc_curl;
  CURLcode res;
  bool have_certs = false;
  struct curl_certinfo *certinfo;
  struct curl_slist *headers = NULL;

  // Get the certificate info for the url
  dpc_curl = curl_easy_init ();

  curl_easy_setopt(dpc_curl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(dpc_curl, CURLOPT_SSL_VERIFYPEER, 0L);
  curl_easy_setopt(dpc_curl, CURLOPT_SSL_VERIFYHOST, 0L);
  curl_easy_setopt(dpc_curl, CURLOPT_VERBOSE, 0L);

  curl_easy_setopt (dpc_curl, CURLOPT_ACCEPT_ENCODING, "deflate");
  headers = curl_slist_append (headers, "Accept: */*");
  headers = curl_slist_append (headers, "Content-Type: text/html");
  curl_easy_setopt (dpc_curl, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt (dpc_curl, CURLOPT_HTTPGET, 1);
  // older versions of curl don't support CURLINFO_CERTINFO reliably
  // so use server return cert info as a backup
  curl_easy_setopt (dpc_curl, CURLOPT_WRITEDATA, http);
  curl_easy_setopt (dpc_curl, CURLOPT_WRITEFUNCTION,
                    http_client::get_data_shim);

  if (s.verbose > 2)
    {
      curl_easy_setopt (dpc_curl, CURLOPT_VERBOSE, 1L);
      curl_easy_setopt (dpc_curl, CURLOPT_DEBUGFUNCTION, trace);
    }
  curl_easy_setopt(dpc_curl, CURLOPT_CERTINFO, 1L);

  res = curl_easy_perform (dpc_curl);

  if (res)
    return false;

  res = curl_easy_getinfo (dpc_curl, CURLINFO_CERTINFO, &certinfo);

  // Create a certificate bundle from the certificate info
  if (!res && certinfo->num_of_certs > 0)
    {
      for (int i = 0; i < certinfo->num_of_certs; i++)
        {
          struct curl_slist *slist;

          for (slist = certinfo->certinfo[i]; slist; slist = slist->next)
            {
              string one_cert;
              string slist_data = string (slist->data);
              size_t cert_begin, cert_end;
              if ((cert_begin = slist_data.find("-----BEGIN CERTIFICATE-----")) == string::npos)
                continue;
              if ((cert_end = slist_data.find("-----END CERTIFICATE-----", cert_begin)) == string::npos)
                continue;
              certs += string (slist_data.substr(cert_begin, cert_end - cert_begin + 28));
              have_certs = true;
            }
        }
    }
  else if (!res && certinfo->num_of_certs == 0)
    {
      json_object *cert_obj;
      // Get the certificate returned by the server
      if  (json_object_object_get_ex (root, "certificate", &cert_obj))
        {
          certs = string (json_object_get_string(cert_obj));
          have_certs = true;
        }
    }


  if (s.verbose >= 2)
    clog << "Server returned certificate chain with: " << certinfo->num_of_certs << " members" << endl;

  curl_easy_cleanup(dpc_curl);
  curl_global_cleanup();

  return have_certs;
}


bool
http_client::download (const std::string & url, http_client::download_type type, bool report_errors, bool cleanup)
{
  struct curl_slist *headers = NULL;

  if (curl)
    curl_easy_reset (curl);
  else
    curl = curl_easy_init ();

  if (s.verbose > 2)
    {
      curl_easy_setopt (curl, CURLOPT_VERBOSE, 1L);
      curl_easy_setopt (curl, CURLOPT_DEBUGFUNCTION, trace);
    }
  curl_easy_setopt (curl, CURLOPT_URL, url.c_str ());
  curl_easy_setopt (curl, CURLOPT_NOSIGNAL, 1); //Prevent "longjmp causes uninitialized stack frame" bug
  curl_easy_setopt (curl, CURLOPT_ACCEPT_ENCODING, "deflate");
  headers = curl_slist_append (headers, "Accept: */*");
  headers = curl_slist_append (headers, "Content-Type: text/html");
  curl_easy_setopt (curl, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt (curl, CURLOPT_HTTPGET, 1);
  curl_easy_setopt (curl, CURLOPT_SSLCERTTYPE, "PEM");
  curl_easy_setopt (curl, CURLOPT_SSL_VERIFYPEER, 1L);
  // Enabling verifyhost  causes a mismatch between "hostname" in the
  // server cert db and "hostname.domain" given as the client url
  curl_easy_setopt (curl, CURLOPT_SSL_VERIFYHOST, 0L);
  curl_easy_setopt (curl, CURLOPT_CAINFO, pem_cert_file.c_str());

  if (type == json_type)
    {
      curl_easy_setopt (curl, CURLOPT_WRITEDATA, http);
      curl_easy_setopt (curl, CURLOPT_WRITEFUNCTION,
                       http_client::get_data_shim);
    }
  else if (type == file_type)
    {
      std::string filename = url;
      std::string filepath;

      if (filename.back() == '/')
        filename.erase(filename.length()-1);
      filepath = s.tmpdir + "/" + filename.substr (filename.rfind ('/')+1);

      if (s.verbose >= 3)
	clog << "Downloaded " + filepath << endl;
      std::FILE *File = std::fopen (filepath.c_str(), "wb");
      curl_easy_setopt (curl, CURLOPT_WRITEDATA, File);
      curl_easy_setopt (curl, CURLOPT_WRITEFUNCTION, http_client::get_file);
    }
  curl_easy_setopt (curl, CURLOPT_HEADERDATA, http);
  curl_easy_setopt (curl, CURLOPT_HEADERFUNCTION, http_client::get_header_shim);

  CURLcode res = curl_easy_perform (curl);

  if (cleanup)
    {
      curl_easy_cleanup(curl);
      curl_global_cleanup();
      curl = 0;
    }

  if (res != CURLE_OK && res != CURLE_GOT_NOTHING)
    {
      if (report_errors)
        clog << curl_easy_strerror (res) << ' ' << url << endl;
      return false;
    }
  else
      return true;
}


// Get the rpm corresponding to SEARCH_FILE

std::string
http_client::get_rpmname (std::string &search_file)
{
    rpmts ts = NULL;
    Header hdr;
    rpmdbMatchIterator mi;
    rpmtd td;

    td = rpmtdNew ();
    ts = rpmtsCreate ();

    rpmReadConfigFiles (NULL, NULL);

    int metrics[] =
      { RPMTAG_NAME, RPMTAG_EVR, RPMTAG_ARCH, RPMTAG_FILENAMES, };

    struct
    {
      string name;
      string evr;
      string arch;
    } rpmhdr;

    bool found = false;
    mi = rpmtsInitIterator (ts, RPMDBI_PACKAGES, NULL, 0);
    while (NULL != (hdr = rpmdbNextIterator (mi)))
      {
	hdr = headerLink(hdr);
        for (unsigned int i = 0; i < (sizeof (metrics) / sizeof (int)); i++)
          {
            headerGet (hdr, metrics[i], td, HEADERGET_EXT);
            switch (td->type)
              {
              case RPM_STRING_TYPE:
                {
                  const char *rpmval = rpmtdGetString (td);
                  switch (metrics[i])
                    {
                    case RPMTAG_NAME:
                      rpmhdr.name = rpmval;
                      break;
                    case RPMTAG_EVR:
                      rpmhdr.evr = rpmval;
                      break;
                    case RPMTAG_ARCH:
                      rpmhdr.arch = rpmval;
                      break;
                    }
                  break;
                }
              case RPM_STRING_ARRAY_TYPE:
		while (rpmtdNext(td) >= 0)
		  {
		    const char *rpmval = rpmtdGetString (td);
		    if (strcmp (rpmval, search_file.c_str()) == 0)
		      {
			found = true;
			break;
		      }
		  }
		break;
              }
	    rpmtdFreeData (td);
            rpmtdReset (td);
	  }
	headerFree (hdr);
	if (found)
	  break;
      }

    rpmFreeCrypto ();
    rpmdbFreeIterator (mi);
    rpmtsFree (ts);
    rpmtdFree (td);

    if (found)
      {
	return rpmhdr.name + "-" + rpmhdr.evr + "." + rpmhdr.arch;
      }

    // There wasn't an rpm that contains SEARCH_FILE. Return the empty
    // string.
    return "";
}


// Put the buildid for DWFLMOD into buildids

int
http_client::process_buildid (Dwfl_Module *dwflmod)
{
  const char *fname;
  dwfl_module_info (dwflmod, NULL, NULL, NULL, NULL, NULL, &fname, NULL);

  GElf_Addr bias;
  int build_id_len = 0;
  unsigned char *build_id_bits;
  GElf_Addr build_id_vaddr;
  string build_id;
  char *result = NULL;
  int code;

  dwfl_module_getelf (dwflmod, &bias);
  build_id_len = dwfl_module_build_id (dwflmod,
      (const unsigned char **)&build_id_bits,
      &build_id_vaddr);

  for (int i = 0; i < build_id_len; i++)
    {
      if (result)
        code = asprintf (&result, "%s%02x", result, *(build_id_bits+i));
      else
        code = asprintf (&result, "%02x", *(build_id_bits+i));
      if (code < 0)
        return 1;
    }

  http->buildids.push_back(make_tuple(fname, result));

  return DWARF_CB_OK;
}


int
http_client::process_buildid_shim (Dwfl_Module *dwflmod,
                 void **userdata __attribute__ ((unused)),
                 const char *name __attribute__ ((unused)),
                 Dwarf_Addr base __attribute__ ((unused)),
                 void *client)
{
  http_client *http = static_cast<http_client *>(client);

  return http->process_buildid (dwflmod);
}


// Do the setup for getting the buildid for FNAME

void
http_client::get_buildid (string fname)
{
  int fd;

  if ((fd = open (fname.c_str(), O_RDONLY)) < 0)
    {
      clog << "can't open " << fname;
      return;
    }

  static const Dwfl_Callbacks callbacks =
    {
      dwfl_build_id_find_elf,
      dwfl_standard_find_debuginfo,
      dwfl_offline_section_address,
      NULL
    };
  Dwfl *dwfl = dwfl_begin (&callbacks);

  if (dwfl == NULL)
    return;

  if (dwfl_report_offline (dwfl, fname.c_str(), fname.c_str(), fd) == NULL)
    return;
  else
    {
      dwfl_report_end (dwfl, NULL, NULL);
      dwfl_getmodules (dwfl, process_buildid_shim, http, 0);
    }
  dwfl_end (dwfl);
  close (fd);
}


void
http_client::get_kernel_buildid (void)
{
  const char *notesfile = "/sys/kernel/notes";
  int fd = open (notesfile, O_RDONLY);
  if (fd < 0)
    return;

  union
  {
      GElf_Nhdr nhdr;
      unsigned char data[8192];
  } buf;

  ssize_t n = read (fd, buf.data, sizeof buf);
  close (fd);

  if (n <= 0)
    return;

  unsigned char *p = buf.data;
  while (p < &buf.data[n])
    {
      /* No translation required since we are reading the native kernel.  */
      GElf_Nhdr *nhdr = (GElf_Nhdr *) p;
      p += sizeof *nhdr;
      unsigned char *name = p;
      p += (nhdr->n_namesz + 3) & -4U;
      unsigned char *bits = p;
      p += (nhdr->n_descsz + 3) & -4U;

      if (p <= &buf.data[n]
          && nhdr->n_type == NT_GNU_BUILD_ID
          && nhdr->n_namesz == sizeof "GNU"
          && !memcmp (name, "GNU", sizeof "GNU"))
        {
          char *result = NULL;
          int code;

          for (unsigned int i = 0; i < nhdr->n_descsz; i++)
            {
              if (result)
                code = asprintf (&result, "%s%02x", result, *(bits+i));
              else
                code = asprintf (&result, "%02x", *(bits+i));
              if (code < 0)
                return;
            }
          http->buildids.push_back(make_tuple("kernel", result));
          break;
        }
    }
}


long
http_client::get_response_code (void)
{
  long response_code = 0;
  curl_easy_getinfo (curl, CURLINFO_RESPONSE_CODE, &response_code);
  return response_code;
}


// Post REQUEST_PARAMETERS, files, modules, buildids to URL

bool
http_client::post (const string & url,
                   vector<tuple<string, string>> & request_parameters)
{
  struct curl_slist *headers = NULL;
  int still_running = false;
  struct curl_httppost *formpost = NULL;
  struct curl_httppost *lastptr = NULL;
  struct json_object *jobj = json_object_new_object();

  // Add parameter info
  // "cmd_args": ["script\/\/path\/linetimes.stp","-v","-v",
  //              "-c\/path\/bench.x","--","process(\"\/path\/bench.x\")","main"]

  string previous_parm_type;
  string previous_json_data;
  auto it = request_parameters.begin ();
  while (it != request_parameters.end ())
    {
      string parm_type = get<0>(*it);
      string parm_data = get<1>(*it);
      struct json_object *json_data = json_object_new_string(parm_data.c_str());
      if (parm_type == previous_parm_type)
        {
          // convert original singleton to an array
          struct json_object *jarr = json_object_new_array();
          json_data = json_object_new_string(previous_json_data.c_str());
          json_object_array_add(jarr, json_data);
          while (parm_type == previous_parm_type)
            {
              json_data = json_object_new_string(parm_data.c_str());
              json_object_array_add(jarr, json_data);
              previous_parm_type = parm_type;
              previous_json_data = parm_data;
              it++;
              parm_type = get<0>(*it);
              parm_data = get<1>(*it);
            }
          json_object_object_add(jobj, previous_parm_type.c_str(), jarr);
          continue;
        }
      else
        json_object_object_add(jobj, parm_type.c_str(), json_data);
      previous_parm_type = parm_type;
      previous_json_data = parm_data;
      it++;
    }

  // Fill in the file upload field; libcurl will load data from the
  // given file name.
  for (auto it = files.begin (); it != files.end (); ++it)
    {
      string filename = (*it);
      string filebase = basename (filename.c_str());

      curl_formadd (&formpost, &lastptr,
		    CURLFORM_COPYNAME, filebase.c_str(),
		    CURLFORM_FILE, filename.c_str(),
		    CURLFORM_END);
      curl_formadd (&formpost, &lastptr,
                    CURLFORM_COPYNAME, "files",
                    CURLFORM_COPYCONTENTS, filename.c_str(),
                    CURLFORM_END);
    }

  // Add package info
  //   "file_info": [ { "file_pkg": "kernel-4.14.0-0.rc4.git4.1.fc28.x86_64",
  //                       "file_name": "kernel",
  //                       "build_id": "ef7210ee3a447c798c3548102b82665f03ef241f" },
  //                  { "file_pkg": "foo-1.1.x86_64",
  //                       "file_name": "/usr/bin/foo",
  //                       "build_id": "deadbeef" }
  //                ]

  int bid_idx = 0;

  struct json_object *jarr = json_object_new_array();
  for (auto it = modules.begin (); it != modules.end (); ++it, ++bid_idx)
    {
      struct json_object *jfobj = json_object_new_object();
      string pkg = (*it);
      string name = std::get<0>(buildids[bid_idx]);
      string build_id = std::get<1>(buildids[bid_idx]);

      json_object_object_add (jfobj, "file_name", json_object_new_string (name.c_str()));
      json_object_object_add (jfobj, "file_pkg", json_object_new_string (pkg.c_str()));
      json_object_object_add (jfobj, "build_id", json_object_new_string (build_id.c_str()));
      json_object_array_add (jarr, jfobj);
    }
  json_object_object_add(jobj, "file_info", jarr);


  // Add environment variables info
  // "env_vars": {"LANG":"en_US.UTF-8","LC_MESSAGES":"en_US.UTF-8"}

  if (! http->env_vars.empty())
    {
      struct json_object *jlvobj = json_object_new_object();
      for (auto i = http->env_vars.begin();
          i != http->env_vars.end();
          ++i)
        {
          string name = get<0>(*i);
          string value = get<1>(*i);
          json_object_object_add (jlvobj, name.c_str(), json_object_new_string(value.c_str()));
        }
      if (http->env_vars.size())
        json_object_object_add (jobj, "env_vars", jlvobj);
    }

  curl_formadd (&formpost, &lastptr,
      CURLFORM_COPYNAME, "command_environment",
      CURLFORM_CONTENTTYPE, "application/json",
      CURLFORM_COPYCONTENTS,
      json_object_to_json_string_ext (jobj, JSON_C_TO_STRING_PLAIN),
      CURLFORM_END);
  json_object_put(jobj);

  headers = curl_slist_append (headers, "Expect:");

  curl_easy_setopt (curl, CURLOPT_URL, url.c_str());
  curl_easy_setopt (curl, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt (curl, CURLOPT_HTTPPOST, formpost);

  CURLM *multi_handle = curl_multi_init();
  curl_multi_add_handle (multi_handle, curl);
  curl_multi_perform (multi_handle, &still_running);
  do {
      struct timeval timeout;
      int rc; // select() return code
      CURLMcode mc; // curl_multi_fdset() return code

      fd_set fdread;
      fd_set fdwrite;
      fd_set fdexcep;
      int maxfd = -1;

      long curl_timeo = -1;

      FD_ZERO (&fdread);
      FD_ZERO (&fdwrite);
      FD_ZERO (&fdexcep);

      // set a suitable timeout to play around with
      timeout.tv_sec = 1;
      timeout.tv_usec = 0;

      curl_multi_timeout (multi_handle, &curl_timeo);
      if (curl_timeo >= 0)
        {
          timeout.tv_sec = curl_timeo / 1000;
          if (timeout.tv_sec > 1)
            timeout.tv_sec = 1;
          else
            timeout.tv_usec = (curl_timeo % 1000) * 1000;
        }

      // get file descriptors from the transfers
      mc = curl_multi_fdset (multi_handle, &fdread, &fdwrite, &fdexcep, &maxfd);

      if (mc != CURLM_OK)
        {
          clog << "curl_multi_fdset() failed" << curl_multi_strerror (mc) << endl;
          return false;
        }

      /* On success the value of maxfd is guaranteed to be >= -1. We call
         select(maxfd + 1, ...); specially in case of (maxfd == -1) there are
         no fds ready yet so we call select(0, ...)to sleep 100ms,
         the minimum suggested value */

      if (maxfd == -1)
        {
          struct timeval wait = { 0, 100 * 1000 }; // 100ms
          rc = select (0, NULL, NULL, NULL, &wait);
        }
      else
        rc = select (maxfd+1, &fdread, &fdwrite, &fdexcep, &timeout);

      switch (rc)
      {
      case -1:
        /* select error */
        break;
      case 0:
      default:
        curl_multi_perform (multi_handle, &still_running);
        break;
      }
  } while (still_running);

  curl_multi_cleanup (multi_handle);
  curl_formfree (formpost);
  curl_slist_free_all (headers);

  return true;
}


//  Add FILE to files
void
http_client::add_file (std::string filename)
{
  files.push_back (filename);
}


// Add MODULE to modules

void
http_client::add_module (std::string module)
{
  modules.push_back (module);
}


// Add the server certificate to the client certificate database

bool
http_client::add_server_cert_to_client (string &tmpdir, db_init_types db_init_type)
{
  const char *certificate;
  json_object *cert_obj;

  // Get the certificate returned by the server
  if  (json_object_object_get_ex (root, "certificate", &cert_obj))
    certificate = json_object_get_string(cert_obj);
  else
    return false;
  string pem_tmp = tmpdir + "pemXXXXXX";
  int fd = mkstemp ((char*)pem_tmp.c_str());
  close(fd);
  std::ofstream pem_out(pem_tmp);
  pem_out << certificate;
  pem_out.close();

  // Add the certificate to the client nss certificate database
  if (add_client_cert(pem_tmp, local_client_cert_db_path(), db_init_type) == SECSuccess)
    {
      remove_file_or_dir (pem_tmp.c_str());
      return true;
    }
  return false;
 }

// Ask the server to delete a URL.

bool
http_client::delete_op (const std::string & url)
{
  curl = curl_easy_init ();
  if (s.verbose > 2)
    {
      curl_easy_setopt (curl, CURLOPT_VERBOSE, 1L);
      curl_easy_setopt (curl, CURLOPT_DEBUGFUNCTION, trace);
    }
  curl_easy_setopt (curl, CURLOPT_URL, url.c_str ());
  curl_easy_setopt (curl, CURLOPT_NOSIGNAL, 1); //Prevent "longjmp causes uninitialized stack frame" bug
  curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");

  CURLcode res = curl_easy_perform (curl);
  if (res != CURLE_OK)
    {
      clog << "curl_easy_perform() failed: " << curl_easy_strerror (res)
	   << endl;
      return false;
    }
  return true;
}


// Can a certificate having trust 'this_cert_trust' be handled by the corresponding host

bool
http_client::check_trust (enum cert_type this_cert_type, vector<compile_server_info> &specified_servers)
{
  vector<compile_server_info> server_list;

  string cert_db_path;
  string cert_string;
    

  if (this_cert_type == signer_trust)
    {
      cert_db_path = signing_cert_db_path ();
      cert_string = "signing";
    }
  else if (this_cert_type == ssl_trust)
      {
	cert_db_path = local_client_cert_db_path ();
	cert_string = "trusted";
      }
  
  get_server_info_from_db (s, server_list, cert_db_path);
  vector<compile_server_info>::iterator i = specified_servers.begin ();
  while (i != specified_servers.end ())
    {
      bool have_match = false;
      for (vector<compile_server_info>::const_iterator j = server_list.begin ();
	   j != server_list.end ();
	   ++j)
	{
	  if (j->host_name == i->host_name
	      || j->host_name == i->unresolved_host_name.substr(0,j->host_name.length()))
	    {
	      have_match = true;
	      break;
	    }
	}
      if (!have_match)
	i = specified_servers.erase (i);
      else
	++i;
    }
  if (specified_servers.size() == 0)
    {
      clog << "No matching " << cert_string << " server";
      if (server_list.size() > 0)
        clog << "; the " << cert_string << " servers are\n" << server_list;
      clog << endl;
      return false;
    }
  else
    return true;
}


http_client_backend::http_client_backend (systemtap_session &s)
  : client_backend(s), files_seen(false)
{
  server_tmpdir = s.tmpdir;
}

int
http_client_backend::initialize ()
{
  if (!http)
    http = new http_client (s);
  request_parameters.clear();

  return 0;
}

// Symbolically link the given file or directory into the client's temp
// directory under the given subdirectory.
//
// We need to do this even for the http client/server so that we can
// fully handle systemtap's complexity. A tricky example of this
// complexity would be something like "stap -I tapset_dir script.stp",
// where "tapset_dir" is empty. You can transfer files with a POST,
// but you can't really indicate an empty directory.
//
// So, we'll handle this like the NSS client does - build up a
// directory of all the files we need to transfer over to the server
// and zip it up and send the one zip file.
int
http_client_backend::include_file_or_directory (const string &subdir,
						const string &path,
						const bool add_arg)
{
  // Must predeclare these because we do use 'goto done' to
  // exit from error situations.
  vector<string> components;
  string name;
  int rc = 0;

  // Canonicalize the given path and remove the leading /.
  string rpath;
  char *cpath = canonicalize_file_name (path.c_str ());
  if (! cpath)
    {
      // It can not be canonicalized. Use the name relative to
      // the current working directory and let the server deal with it.
      char cwd[PATH_MAX];
      if (getcwd (cwd, sizeof (cwd)) == NULL)
	{
	  rpath = path;
	  rc = 1;
	  goto done;
	}
	rpath = string (cwd) + "/" + path;
    }
  else
    {
      // It can be canonicalized. Use the canonicalized name and add this
      // file or directory to the request package.
      rpath = cpath;
      free (cpath);

      // Including / would require special handling in the code below and
      // is a bad idea anyway. Let's not allow it.
      if (rpath == "/")
	{
	  if (rpath != path)
	    clog << _F("%s resolves to %s\n", path.c_str (), rpath.c_str ());
	  clog << _F("Unable to send %s to the server\n", path.c_str ());
	  return 1;
	}

      // First create the requested subdirectory (if there is one).
      if (! subdir.empty())
        {
	  name = client_tmpdir + "/" + subdir;
	  rc = create_dir (name.c_str ());
	  if (rc) goto done;
	}
      else
        {
	  name = client_tmpdir;
	}

      // Now create each component of the path within the sub directory.
      assert (rpath[0] == '/');
      tokenize (rpath.substr (1), components, "/");
      assert (components.size () >= 1);
      unsigned i;
      for (i = 0; i < components.size() - 1; ++i)
	{
	  if (components[i].empty ())
	    continue; // embedded '//'
	  name += "/" + components[i];
	  rc = create_dir (name.c_str ());
	  if (rc) goto done;
	}

      // Now make a symbolic link to the actual file or directory.
      assert (i == components.size () - 1);
      name += "/" + components[i];
      rc = symlink (rpath.c_str (), name.c_str ());
      if (rc) goto done;
    }

  // If the caller asks us, add this file or directory to the arguments.
  if (add_arg)
    rc = add_cmd_arg (subdir + "/" + rpath.substr (1));

 done:
  if (rc != 0)
    {
      const char* e = strerror (errno);
      clog << "ERROR: unable to add "
	   << rpath
	   << " to temp directory as "
	   << name << ": " << e
	   << endl;
    }
  else
    {
      files_seen = true;
    }
  return rc;
}

int
http_client_backend::package_request ()
{
  int rc = 0;

  http->add_module ("kernel-" + s.kernel_release);
  http->get_kernel_buildid ();

  for (set<std::string>::const_iterator i = s.unwindsym_modules.begin();
      i != s.unwindsym_modules.end();
      ++i)
    {
      string module = (*i);
      if (module != "kernel")
        {
	  string rpmname = http->get_rpmname (module);
	  if (! rpmname.empty())
	    {
	      http->get_buildid (module);
	      http->add_module (rpmname);
	    }
	  else if (module[0] == '/')
	    {
		include_file_or_directory ("files", module, false);
	    }
	}
    }

  // Package up the temporary directory into a zip file, if needed.
  if (files_seen)
    {
      string client_zipfile = client_tmpdir + ".zip";
      string cmd = "cd " + cmdstr_quoted(client_tmpdir) + " && zip -qr "
	  + cmdstr_quoted(client_zipfile) + " *";
      vector<string> sh_cmd { "sh", "-c", cmd };
      rc = stap_system (s.verbose, sh_cmd);

      if (rc == 0)
	http->add_file(client_zipfile);
    }
  return rc;
}


int
http_client_backend::find_and_connect_to_server ()
{
  const string cert_db = local_client_cert_db_path ();
  const string nick = server_cert_nickname ();

  if (s.verbose >= 2)
    clog << "connecting to server using cert db " + cert_db << endl;

  vector<compile_server_info> specified_servers;
  nss_get_specified_server_info (s, specified_servers);

  if (! pr_contains (s.privilege, pr_stapdev))
    if (! http->check_trust (http->signer_trust, specified_servers))
      return 1;

  if (! http->check_trust (http->ssl_trust, specified_servers))
    return 1;

  for (vector<compile_server_info>::iterator i = specified_servers.begin ();
       i != specified_servers.end ();
       ++i)
    {
      // Try to connect to the server. We'll try to grab the base
      // directory of the server just to see if we can make a
      // connection.
      __label__ TRY_NEXT_SERVER;
      string pem_cert;
      bool add_cert = false;
      string url = "https://" + i->host_specification();
      http->host = i->unresolved_host_name;

      int download_tries;
      if (get_pem_cert(cert_db, nick, http->host, pem_cert) == true)
        download_tries = 2; // 1st try cert db 2nd download cert from server
      else
        download_tries = 1; // download cert from server

      while (download_tries)
        {
          if (download_tries == 1)
            {
              pem_cert = "";
              if (http->download_pem_cert (url, pem_cert) == false)
                goto TRY_NEXT_SERVER;
              else
                add_cert = true;
            }
          string pem_tmp = client_tmpdir + "/pemXXXXXX";
          int fd = mkstemp ((char*)pem_tmp.c_str());
          close(fd);
          std::ofstream pem_out(pem_tmp);
          pem_out << pem_cert;
          pem_out.close();
          http->pem_cert_file = pem_tmp;
          // Similar to CURLOPT_VERIFYHOST: compare source alternate names to hostname
          if (have_san_match (url, pem_cert) == false)
            goto TRY_NEXT_SERVER;

          // curl invocation for a download must be the same as the preceding post
          if (http->download (url + "/", http->json_type, true, false) == true)
            break;
          remove_file_or_dir (pem_tmp.c_str());
          download_tries -= 1;
        }

      // FIXME: The server returns its version number. We might
      // need to check it for compatibility.

      // Send our build request.
      if (http->post (url + "/builds", request_parameters))
        {
          s.winning_server = url;
          http->host = url;
          if (add_cert)
            http->add_server_cert_to_client (client_tmpdir, db_nssinitcontext);
          return 0;
        }
      TRY_NEXT_SERVER:;
    }

  return 1;
}

int
http_client_backend::unpack_response ()
{
  std::string build_uri;
  std::map<std::string, std::string>::iterator it_loc;
  it_loc = http->header_values.find("Location");
  if (it_loc == http->header_values.end())
    {
      clog << "Cannot get location from server" << endl;
      return 1;
    }
  build_uri = http->host + http->header_values["Location"];

  if (s.verbose >= 2)
    clog << "Initial response code: " << http->get_response_code() << endl;
  while (true)
    {
      auto it = http->header_values.find("Retry-After");
      if (it == http->header_values.end())
        {
	  clog << "No retry-after?" << endl;
	  break;
	}
      int retry = std::stoi(http->header_values["Retry-After"], nullptr, 10);
      if (s.verbose >= 2)
	clog << "Waiting " << retry << " seconds" << endl;
      sleep (retry);
      if (http->download (http->host + http->header_values["Location"],
			  http->json_type, true, false))
        {
	  // We need to wait until we get a 303 (See Other)
	  long response_code = http->get_response_code();
	  if (s.verbose >= 2)
	    clog << "Response code: " << response_code << endl;
	  if (response_code == 200)
	    continue;
	  else if (response_code == 303)
	    break;
	  else
	    {
	      clog << "Received a unhandled response code "
		   << response_code << endl;
	      return 1;
	    }
	}
    }

  // If we're here, we got a '303' (See Other). Read the "other"
  // location, which should contain our results.
  if (! http->download (http->host + http->header_values["Location"],
			http->json_type, true, false))
    {
      clog << "Couldn't read result information" << endl;
      return 1;
    }

  // Get the server version number.
  json_object *ver_obj;
  json_bool jfound = json_object_object_get_ex (http->root, "version",
						&ver_obj);
  if (jfound)
    {
      server_version = json_object_get_string(ver_obj);
    }
  else
    {
      clog << "Couldn't find 'version' in JSON results data" << endl;
      return 1;
    }

  // Get the return code information.
  json_object *rc_obj;
  jfound = json_object_object_get_ex (http->root, "rc", &rc_obj);
  if (jfound)
    {
      int rc = json_object_get_int(rc_obj);
      write_to_file(s.tmpdir + "/rc", rc);
    }
  else
    {
      clog << "Couldn't find 'rc' in JSON results data" << endl;
      return 1;
    }

  // Download each item in the optional 'files' array. This is
  // optional since not all stap invocations produce an output file
  // (like a module).
  json_object *files;
  json_object_object_get_ex (http->root, "files", &files);
  if (files)
    {
      for (size_t k = 0; k < (size_t)json_object_array_length (files); k++)
        {
	  json_object *files_element = json_object_array_get_idx (files, k);
	  json_object *loc;
	  jfound = json_object_object_get_ex (files_element, "location", &loc);
	  string location = json_object_get_string (loc);
	  http->download (http->host + location, http->file_type, true, false);
	}
    }

  // Output stdout and stderr.
  json_object *loc_obj;
  jfound = json_object_object_get_ex (http->root, "stderr_location", &loc_obj);
  if (jfound)
    {
      string loc_str = json_object_get_string (loc_obj);
      http->download (http->host + loc_str, http->file_type, true, false);
    }
  else
    {
      clog << "Couldn't find 'stderr' in JSON results data" << endl;
      return 1;
    }

  jfound = json_object_object_get_ex (http->root, "stdout_location", &loc_obj);
  if (jfound)
    {
      string loc_str = json_object_get_string (loc_obj);
      http->download (http->host + loc_str, http->file_type, true, false);
    }
  else
    {
      clog << "Couldn't find 'stdout' in JSON results data" << endl;
      return 1;
    }

  delete http;
  return 0;
}


int
http_client_backend::add_protocol_version (const std::string &version)
{
  // Add the protocol version (so the server can ensure we're
  // compatible).
  request_parameters.push_back(make_tuple("version", version));
  return 0;
}


int
http_client_backend::add_sysinfo ()
{
  request_parameters.push_back(make_tuple("kver", s.kernel_release));
  request_parameters.push_back(make_tuple("arch", s.architecture));

  vector<string> distro_info;

  get_distro_info (distro_info);
  if (! distro_info.empty())
    {
      std::replace(distro_info[0].begin(), distro_info[0].end(), '\n', ' ');
      std::replace(distro_info[1].begin(), distro_info[1].end(), '\n', ' ');
      request_parameters.push_back(make_tuple("distro_name", distro_info[0]));
      request_parameters.push_back(make_tuple("distro_version", distro_info[1]));
    }
  return 0;
}

int
http_client_backend::add_tmpdir_file (const std::string &)
{
  files_seen = true;
  return 0;
}

int
http_client_backend::add_cmd_arg (const std::string &arg)
{
  request_parameters.push_back(make_tuple("cmd_args", arg));
  return 0;
}

void
http_client_backend::add_localization_variable (const std::string &name,
					        const std::string &value)
{
  http->env_vars.push_back(make_tuple(name, value));
  return;
}

void
http_client_backend::add_mok_fingerprint (const std::string &)
{
  // FIXME: We'll probably just add to the request_parameters here.
  return;
}

void
http_client_backend::fill_in_server_info (compile_server_info &info)
{
  const string cert_db = local_client_cert_db_path ();
  const string nick = server_cert_nickname ();
  string host = info.unresolved_host_name;
  if (info.port == 0)
    // Sync with httpd/main.cxx
    info.port = 1234;
  string url = "https://" + host + ":" + std::to_string(info.port);
  string pem_cert;

  if (host.empty())
    return;

  if (s.verbose >= 2)
    {
      char hostname[NI_MAXHOST];
      memset (&hostname, '\0', NI_MAXHOST);
      PR_NetAddrToString(&info.address, hostname, NI_MAXHOST);
      clog << "getting server info for " + url + " " + hostname + " using cert db " + cert_db << endl;
    }

  // Try to get the server certificate and the base
  // directory of the server just to see if we can make a
  // connection.
  int download_tries;
  // Obtain server info based on network address instead of host name?
  if (file_exists (cert_db) == true && get_pem_cert(cert_db, nick, http->host, pem_cert) == true)
    download_tries = 2; // 1st try cert db 2nd download cert from server
  else
    download_tries = 1; // download cert from server

  while (download_tries)
    {
      if (download_tries == 1)
        {
          pem_cert = "";
          if (http->download_pem_cert (url, pem_cert) == false)
            return;
        }
      string pem_tmp = s.tmpdir + "/pemXXXXXX";
      int fd = mkstemp ((char*)pem_tmp.c_str());
      close(fd);
      std::ofstream pem_out(pem_tmp);
      pem_out << pem_cert;
      pem_out.close();
      http->pem_cert_file = pem_tmp;
      // Similar to CURLOPT_VERIFYHOST: compare source alternate names to hostname
      if (have_san_match (url, pem_cert) == false)
        return;

      // curl invocation for a download must be the same as the preceding post
      if (http->download (url + "/", http->json_type, false, true) == true)
        break;
      remove_file_or_dir (pem_tmp.c_str());
      download_tries -= 1;
    }

  json_object *ver_obj;
  json_bool jfound;

  // Get the server version number.
  jfound = json_object_object_get_ex (http->root, "version", &ver_obj);
  if (jfound)
    info.version = json_object_get_string(ver_obj);

  // Get the server arch.
  jfound = json_object_object_get_ex (http->root, "arch", &ver_obj);
  if (jfound)
    info.sysinfo = json_object_get_string(ver_obj);

  // Get the server certificate info.
  jfound = json_object_object_get_ex (http->root, "cert_info", &ver_obj);
  if (jfound)
    info.certinfo = json_object_get_string(ver_obj);

  // If the download worked, this server is obviously online.
  nss_add_online_server_info (s, info);
}

int
http_client_backend::trust_server_info (const compile_server_info &info)
{
  const string cert_db = local_client_cert_db_path ();
  const string nick = server_cert_nickname ();
  string pem_cert;
  string host = info.unresolved_host_name;
  string url = "https://" + host + ":" + std::to_string(info.port);

  if (s.verbose >= 2)
    clog << "getting server trust for " + url + " using cert db " + cert_db << endl;

  if (http->download_pem_cert (url, pem_cert) == false)
    return 1;

  string pem_tmp = s.tmpdir + "/pemXXXXXX";
  int fd = mkstemp ((char*)pem_tmp.c_str());
  close(fd);
  std::ofstream pem_out(pem_tmp);
  pem_out << pem_cert;
  pem_out.close();
  http->pem_cert_file = pem_tmp;
  // Similar to CURLOPT_VERIFYHOST: compare source alternate names to hostname
  if (have_san_match (url, pem_cert) == false)
    return 1;

  if (http->download (url + "/", http->json_type, false, true))
    http->add_server_cert_to_client (s.tmpdir, db_no_nssinit);

  return 0;
}

#endif /* HAVE_HTTP_SUPPORT */
