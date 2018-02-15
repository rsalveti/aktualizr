#include <stdlib.h>
#include <iostream>
#include <sstream>
#include <string>

#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>
#include <boost/random/random_device.hpp>
#include "json/json.h"

#include "bootstrap.h"
#include "config.h"
#include "crypto.h"
#include "httpclient.h"
#include "logging.h"
#include "utils.h"


namespace bpo = boost::program_options;

void check_info_options(const bpo::options_description &description, const bpo::variables_map &vm) {
  if (vm.count("help") != 0) {
    std::cout << description << '\n';
    exit(EXIT_SUCCESS);
  }
  if (vm.count("version") != 0) {
    std::cout << "Current aktualizr_cert_provider version is: " << AKTUALIZR_VERSION << "\n";
    exit(EXIT_SUCCESS);
  }
}

bpo::variables_map parse_options(int argc, char *argv[]) {
  bpo::options_description description("aktualizr_cert_provider command line options");
  // clang-format off
  description.add_options()
      ("help,h", "print usage")
      ("version,v", "Current aktualizr_cert_provider version")
      ("credentials,c", bpo::value<boost::filesystem::path>()->required(), "zipped credentials file")
      ("device-ca", bpo::value<boost::filesystem::path>(), "path to certificate authority certificate signing device certificates")
      ("device-ca-key", bpo::value<boost::filesystem::path>(), "path to the private key of device certificate authority")
      ("bits", bpo::value<int>(), "size of RSA keys in bits")
      ("days", bpo::value<int>(), "validity term for the certificate in days")
      ("certificate-c", bpo::value<std::string>(), "value for C field in certificate subject name")
      ("certificate-st", bpo::value<std::string>(), "value for ST field in certificate subject name")
      ("certificate-o", bpo::value<std::string>(), "value for O field in certificate subject name")
      ("certificate-cn", bpo::value<std::string>(), "value for CN field in certificate subject name")
      ("target,t", bpo::value<std::string>(), "target device to scp credentials to (or [user@]host)")
      ("port,p", bpo::value<int>(), "target port")
      ("directory,d", bpo::value<boost::filesystem::path>()->default_value("/var/sota/token"), "directory on target to write credentials to")
      ("root-ca,r", "provide root CA")
      ("local,l", bpo::value<boost::filesystem::path>(), "local directory to write credentials to")
      ("config,g", bpo::value<boost::filesystem::path>(), "sota.toml configuration file from which to get file names");
  // clang-format on

  bpo::variables_map vm;
  std::vector<std::string> unregistered_options;
  try {
    bpo::basic_parsed_options<char> parsed_options =
        bpo::command_line_parser(argc, argv).options(description).allow_unregistered().run();
    bpo::store(parsed_options, vm);
    check_info_options(description, vm);
    bpo::notify(vm);
    unregistered_options = bpo::collect_unrecognized(parsed_options.options, bpo::include_positional);
    if (vm.count("help") == 0 && !unregistered_options.empty()) {
      std::cout << description << "\n";
      exit(EXIT_FAILURE);
    }
  } catch (const bpo::required_option &ex) {
    // print the error and append the default commandline option description
    std::cout << ex.what() << std::endl << description;
    exit(EXIT_SUCCESS);
  } catch (const bpo::error &ex) {
    check_info_options(description, vm);

    // print the error message to the standard output too, as the user provided
    // a non-supported commandline option
    std::cout << ex.what() << '\n';

    // set the returnValue, thereby ctest will recognize
    // that something went wrong
    exit(EXIT_FAILURE);
  }

  return vm;
}

template<typename T, void (*destoy)(T*)> class StructGuard {
	public:
		StructGuard(T* guarded_in) {guarded = guarded_in;}	
		~StructGuard() {destroy(guarded);}
		T* get() {return guarded;}
	private:
		T* guarded;
};

// I miss Rust's ? operator
#define SSL_ERROR(description) { \
	std::cerr << description << ERR_error_string(ERR_get_error(), NULL) << std::endl; \
	return false; \
}
bool generate_and_sign(const std::string& cacert_path, const std::string& capkey_path, std::string* pkey, std::string* cert, const bpo::variables_map& commandline_map) {
	bool res = false;

	int rsa_bits = 2048;
	if (commandline_map.count("bits") != 0)
		rsa_bits = (commandline_map["bits"].as<int>());

	int cert_days = 365;
	if (commandline_map.count("days") != 0)
		cert_days = (commandline_map["days"].as<int>());

	std::string newcert_c;
	if (commandline_map.count("certificate-c") != 0) {
		newcert_c = (commandline_map["certificate-c"].as<std::string>());
	} else {
		std::cerr << "certificate-c should be specified when using CA to generate a certificate" << std::endl;
		return false;
	}

	std::string newcert_st;
	if (commandline_map.count("certificate-st") != 0) {
		newcert_st = (commandline_map["certificate-st"].as<std::string>());
	} else {
		std::cerr << "certificate-st should be specified when using CA to generate a certificate" << std::endl;
		return false;
	}

	std::string newcert_o;
	if (commandline_map.count("certificate-o") != 0) {
		newcert_o = (commandline_map["certificate-o"].as<std::string>());
	} else {
		std::cerr << "certificate-o should be specified when using CA to generate a certificate" << std::endl;
		return false;
	}

	std::string newcert_cn;
	if (commandline_map.count("certificate-cn") != 0) {
		newcert_cn = (commandline_map["certificate-cn"].as<std::string>());
	} else {
		std::cerr << "certificate-cn should be specified when using CA to generate a certificate" << std::endl;
		return false;
	}

	// create private key
	EVP_PKEY* certificate_pkey = EVP_PKEY_new();
	if(!certificate_pkey) SSL_ERROR("EVP_PKEY_new failed: ");

	RSA* certificate_rsa = RSA_generate_key(rsa_bits, RSA_F4, nullptr, nullptr);
	if(!certificate_rsa)
		SSL_ERROR("RSA_generate_key failed: ");

	if(!EVP_PKEY_assign_RSA(certificate_pkey, certificate_rsa)) 
		SSL_ERROR("EVP_PKEY_assign_RSA failed: ");

	// create certificate request
	X509_REQ* certificate_req = X509_REQ_new();
	if(!certificate_req)
		SSL_ERROR("X509_REQ_new failed: ");

	if(!X509_REQ_set_pubkey(certificate_req, certificate_pkey))
		SSL_ERROR("X509_REQ_set_pubkey failed: ");

	X509_NAME *subj = X509_NAME_new();
	if(!subj)
		SSL_ERROR("X509_NAME_new failed: ");

	if (!X509_NAME_add_entry_by_txt(subj, "C", MBSTRING_ASC, (const unsigned char*) newcert_c.c_str(), -1, -1, 0))
		SSL_ERROR("X509_NAME_add_entry_by_txt failed: ");

	if (!X509_NAME_add_entry_by_txt(subj, "ST", MBSTRING_ASC, (const unsigned char*) newcert_st.c_str(), -1, -1, 0))
		SSL_ERROR("X509_NAME_add_entry_by_txt failed: ");

	if (!X509_NAME_add_entry_by_txt(subj, "O", MBSTRING_ASC, (const unsigned char*) newcert_o.c_str(), -1, -1, 0))
		SSL_ERROR("X509_NAME_add_entry_by_txt failed: ");

	if (!X509_NAME_add_entry_by_txt(subj, "CN", MBSTRING_ASC, (const unsigned char*) newcert_cn.c_str(), -1, -1, 0))
		SSL_ERROR("X509_NAME_add_entry_by_txt failed: ");
	if (!X509_REQ_set_subject_name(certificate_req, subj))
		SSL_ERROR("X509_REQ_set_subject_name failed: ");

	const EVP_MD* digest = EVP_sha256();
	if (!X509_REQ_sign(certificate_req, certificate_pkey, digest))
		SSL_ERROR("EVP_REQ_sign failed: ");

	// read CA certificate
	X509* ca_certificate;
	{
		std::string cacert_contents = Utils::readFile(cacert_path);
		BIO* bio = BIO_new_mem_buf(cacert_contents.c_str(), (int)(cacert_contents.size()));
		ca_certificate = PEM_read_bio_X509(bio, nullptr, 0, nullptr);
		BIO_free_all(bio);
		if(!ca_certificate)
			std::cerr << "Reading CA certificate failed" <<  "\n";
	}


	// read CA private key
	EVP_PKEY* ca_privkey;
	{
		std::string capkey_contents = Utils::readFile(capkey_path);
		BIO* bio = BIO_new_mem_buf(capkey_contents.c_str(), (int)(capkey_contents.size()));
		ca_privkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
		BIO_free_all(bio);
		if(!ca_privkey)
			SSL_ERROR("PEM_read_bio_PrivateKey failed: ");
	}

	// create certificate from certificate request
	X509* certificate = X509_new();
	if(!certificate)
		SSL_ERROR("X509_new failed: ");

	X509_set_version(certificate, 2); // X509v3

	{
		boost::random::random_device urandom;
		boost::random::uniform_int_distribution<> serial_dist(0, (1UL<<20) - 1);
		ASN1_INTEGER_set(X509_get_serialNumber(certificate), serial_dist(urandom));
	}

	if(!X509_set_subject_name(certificate, subj))
		SSL_ERROR("X509_set_subject_name failed: ");

	X509_NAME* ca_subj = X509_get_subject_name(ca_certificate);
	if(!ca_subj)
		SSL_ERROR("X509_get_subject_name failed: ");

	if(!X509_set_issuer_name(certificate, ca_subj))
		SSL_ERROR("X509_set_issuer_name failed: ");

	if(!X509_set_pubkey(certificate, certificate_pkey))
		SSL_ERROR("X509_set_pubkey failed: ");

	if(!X509_gmtime_adj(X509_get_notBefore(certificate), 0))
		SSL_ERROR("X509_gmtime_adj failed: ");

	if(!X509_gmtime_adj(X509_get_notAfter(certificate), 60*60*24*cert_days))
		SSL_ERROR("X509_gmtime_adj failed: ");

	const EVP_MD* cert_digest = EVP_sha256();
	if(!X509_sign(certificate, ca_privkey, cert_digest))
		SSL_ERROR("X509_sign failed: ");

	{
		char* privkey_buf;
		size_t privkey_len;
		FILE* privkey_file = open_memstream(&privkey_buf, &privkey_len);
		if (!privkey_file) {
			std::cerr << "Error opening memstream" << std::endl;
			goto error;
		}
		int ret = PEM_write_RSAPrivateKey(privkey_file, certificate_rsa, NULL, NULL, 0, NULL, NULL);
		fclose(privkey_file);
		if(!ret) {
			std::cerr << "PEM_write_RSAPrivateKey" << std::endl;
			goto error;
		}
		*pkey = std::string(privkey_buf, privkey_len);
	}
	{
		char* cert_buf;
		size_t cert_len;
		FILE* cert_file = open_memstream(&cert_buf, &cert_len);
		if (!cert_file) {
			std::cerr << "Error opening memstream" << std::endl;
			goto error;
		}
		int ret = PEM_write_X509(cert_file, certificate);
		fclose(cert_file);
		if(!ret) {
			std::cerr << "PEM_write_X509" << std::endl;
			goto error;
		}
		*cert = std::string(cert_buf, cert_len);
	}


	res = true;
error: // Bad, bad programmer. Write wrappers around openssl structures instead
	return res;
}

int main(int argc, char *argv[]) {
  logger_init();
  logger_set_threshold(static_cast<boost::log::trivial::severity_level>(2));

  bpo::variables_map commandline_map = parse_options(argc, argv);

  boost::filesystem::path credentials_path = commandline_map["credentials"].as<boost::filesystem::path>();
  std::string target = "";
  if (commandline_map.count("target") != 0) {
    target = commandline_map["target"].as<std::string>();
  }
  int port = 0;
  if (commandline_map.count("port") != 0) {
    port = (commandline_map["port"].as<int>());
  }
  boost::filesystem::path directory = commandline_map["directory"].as<boost::filesystem::path>();
  bool provide_ca = commandline_map.count("root-ca") != 0;
  boost::filesystem::path local_dir;
  if (commandline_map.count("local") != 0) {
    local_dir = commandline_map["local"].as<boost::filesystem::path>();
  }
  boost::filesystem::path config_path = "";
  if (commandline_map.count("config") != 0) {
    config_path = commandline_map["config"].as<boost::filesystem::path>();
  }
  
  boost::filesystem::path device_ca_path = "";
  if (commandline_map.count("device-ca") != 0) {
    device_ca_path = commandline_map["device-ca"].as<boost::filesystem::path>();
  }

  boost::filesystem::path device_ca_key_path = "";
  if (commandline_map.count("device-ca-key") != 0) {
    device_ca_key_path = commandline_map["device-ca-key"].as<boost::filesystem::path>();
  }

  if(device_ca_path.empty() != device_ca_key_path.empty()) {
	std::cerr << "device-ca and device-ca-key options should be used together" << std::endl;
	return 1;
  }

  boost::filesystem::path pkey_file = "pkey.pem";
  boost::filesystem::path cert_file = "client.pem";
  boost::filesystem::path ca_file = "root.crt";
  if (!config_path.empty()) {
    Config config(config_path);
    // Strip any relative directories. Assume everything belongs in one
    // directory for now.
    pkey_file = config.storage.tls_pkey_path.filename();
    cert_file = config.storage.tls_clientcert_path.filename();
    if (provide_ca) {
      ca_file = config.storage.tls_cacert_path.filename();
    }
  }

  TemporaryFile tmp_pkey_file(pkey_file.string());
  TemporaryFile tmp_cert_file(cert_file.string());
  TemporaryFile tmp_ca_file(ca_file.string());

  std::string pkey;
  std::string cert;
  std::string ca;

  if(device_ca_path.empty()) { // no device ca => autoprovision
	  std::string device_id = Utils::genPrettyName();
	  std::cout << "Random device ID is " << device_id << "\n";

	  Bootstrap boot(credentials_path, "");
	  HttpClient http;
	  Json::Value data;
	  data["deviceId"] = device_id;
	  data["ttl"] = 36000;
	  std::string serverUrl = Bootstrap::readServerUrl(credentials_path);

	  std::cout << "Provisioning against server...\n";
	  http.setCerts(boot.getCa(), kFile, boot.getCert(), kFile, boot.getPkey(), kFile);
	  HttpResponse response = http.post(serverUrl + "/devices", data);
	  if (!response.isOk()) {
		  Json::Value resp_code = response.getJson()["code"];
		  if (resp_code.isString() && resp_code.asString() == "device_already_registered") {
			  std::cout << "Device ID" << device_id << "is occupied.\n";
			  return -1;
		  } else {
			  std::cout << "Provisioning failed, response: " << response.body << "\n";
			  return -1;
		  }
	  }
	  std::cout << "...success\n";

	  FILE *device_p12 = fmemopen(const_cast<char *>(response.body.c_str()), response.body.size(), "rb");
	  if (!Crypto::parseP12(device_p12, "", &pkey, &cert, &ca)) {
		  return -1;
	  }
	  fclose(device_p12);

  } else { // device CA set => generate and sign a new certificate
	if(!generate_and_sign(device_ca_path.native(), device_ca_key_path.native(), &pkey, &cert, commandline_map))
		return 1;
	// TODO: extract root CA from credentials.zip
  }

  tmp_pkey_file.PutContents(pkey);
  tmp_cert_file.PutContents(cert);
  if (provide_ca) {
    tmp_ca_file.PutContents(ca);
  }

  if (!local_dir.empty()) {
    std::cout << "Writing client certificate and keys to " << local_dir << " ...\n";
    if (boost::filesystem::exists(local_dir)) {
      boost::filesystem::remove(local_dir / pkey_file);
      boost::filesystem::remove(local_dir / cert_file);
      if (provide_ca) {
        boost::filesystem::remove(local_dir / ca_file);
      }
    } else {
      boost::filesystem::create_directory(local_dir);
    }
    boost::filesystem::copy_file(tmp_pkey_file.PathString(), local_dir / pkey_file);
    boost::filesystem::copy_file(tmp_cert_file.PathString(), local_dir / cert_file);
    if (provide_ca) {
      boost::filesystem::copy_file(tmp_ca_file.PathString(), local_dir / ca_file);
    }
    std::cout << "...success\n";
  }

  if (!target.empty()) {
    std::cout << "Copying client certificate and keys to " << target << ":" << directory;
    if (port) {
      std::cout << " on port " << port;
    }
    std::cout << " ...\n";
    std::ostringstream ssh_prefix;
    std::ostringstream scp_prefix;
    ssh_prefix << "ssh ";
    scp_prefix << "scp ";
    if (port) {
      ssh_prefix << "-p " << port << " ";
      scp_prefix << "-P " << port << " ";
    }

    int ret = system((ssh_prefix.str() + target + " mkdir -p " + directory.string()).c_str());
    if (ret != 0) {
      std::cout << "Error connecting to target device: " << ret << "\n";
      return -1;
    }

    ret = system((scp_prefix.str() + tmp_pkey_file.PathString() + " " + target + ":" + (directory / pkey_file).string())
                     .c_str());
    if (ret != 0) {
      std::cout << "Error copying files to target device: " << ret << "\n";
    }

    ret = system((scp_prefix.str() + tmp_cert_file.PathString() + " " + target + ":" + (directory / cert_file).string())
                     .c_str());
    if (ret != 0) {
      std::cout << "Error copying files to target device: " << ret << "\n";
    }

    if (provide_ca) {
      ret = system(
          (scp_prefix.str() + tmp_ca_file.PathString() + " " + target + ":" + (directory / ca_file).string()).c_str());
      if (ret != 0) {
        std::cout << "Error copying files to target device: " << ret << "\n";
      }
    }

    std::cout << "...success\n";
  }

  return 0;
}
