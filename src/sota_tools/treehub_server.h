#ifndef SOTA_CLIENT_TOOLS_TREEHUB_SERVER_H_
#define SOTA_CLIENT_TOOLS_TREEHUB_SERVER_H_

#include <string>

#include <curl/curl.h>

#include "server_credentials.h"
#include "utils.h"

class TreehubServer {
 public:
  TreehubServer();
  void SetToken(const std::string &token);
  void SetCerts(const std::string &root_cert, const std::string &client_cert, const std::string &client_key);
  void SetAuthBasic(const std::string &username, const std::string &password);

  void InjectIntoCurl(const std::string &url_suffix, CURL *curl_handle, bool tufrepo = false) const;

  void ca_certs(const std::string &cacerts) { ca_certs_ = cacerts; }
  void root_url(const std::string &_root_url);
  void repo_url(const std::string &_repo_url);
  std::string root_url() { return root_url_; };

 private:
  std::string ca_certs_;
  std::string root_url_;
  std::string repo_url_;
  std::string username_;
  std::string password_;
  std::string root_cert_;
  TemporaryFile root_cert_path_;
  TemporaryFile client_cert_path_;
  TemporaryFile client_key_path_;
  AuthMethod method_;
  struct curl_slist auth_header_;
  // Don't modify auth_header_contents_ without updating the pointer in
  // auth_header_
  std::string auth_header_contents_;
  struct curl_slist force_header_;
  // Don't modify force_header_contents_ without updating the pointer in
  // force_header_
  std::string force_header_contents_;
};

// vim: set tabstop=2 shiftwidth=2 expandtab:
#endif  // SOTA_CLIENT_TOOLS_TREEHUB_SERVER_H_
