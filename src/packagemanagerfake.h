#ifndef PACKAGEMANAGERFAKE_H_
#define PACKAGEMANAGERFAKE_H_

#include <boost/make_shared.hpp>
#include <boost/shared_ptr.hpp>

#include "packagemanagerinterface.h"

class PackageFake : public PackageInterface {
 public:
  PackageFake(const std::string &ref_name_in, const std::string &refhash_in, const std::string &treehub_in)
      : PackageInterface(ref_name_in, refhash_in, treehub_in) {}

  ~PackageFake() {}

  data::InstallOutcome install(const data::PackageManagerCredentials &cred, const PackageConfig &pconfig) const {
    (void)cred;
    (void)pconfig;
    return data::InstallOutcome(data::OK, "Good");
  }
};

class PackageManagerFake : public PackageManagerInterface {
 public:
  Json::Value getInstalledPackages() {
    Json::Value packages(Json::arrayValue);
    return packages;
  }

  std::string getCurrent() { return "hash"; }

  boost::shared_ptr<PackageInterface> makePackage(const std::string &branch_name_in, const std::string &refhash_in,
                                                  const std::string &treehub_in) {
    return boost::make_shared<PackageFake>(branch_name_in, refhash_in, treehub_in);
  }
};

#endif  // PACKAGEMANAGERFAKE_H_
