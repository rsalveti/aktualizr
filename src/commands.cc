#include "commands.h"
#include <boost/make_shared.hpp>

namespace command {

Json::Value BaseCommand::toJson() {
  Json::Value json;
  json["variant"] = variant;
  json["fields"] = Json::Value(Json::arrayValue);
  return json;
}

boost::shared_ptr<BaseCommand> BaseCommand::fromPicoJson(const picojson::value& json) {
  std::string variant = json.get("variant").to_str();
  std::string data = json.serialize(false);
  if (variant == "Shutdown") {
    return boost::make_shared<Shutdown>();
  } else if (variant == "GetUpdateRequests") {
    return boost::make_shared<GetUpdateRequests>();
  } else if (variant == "StartDownload") {
    return boost::make_shared<StartDownload>(StartDownload::fromJson(data));
  } else if (variant == "AbortDownload") {
    return boost::make_shared<AbortDownload>(AbortDownload::fromJson(data));
  } else if (variant == "SendUpdateReport") {
    return boost::make_shared<SendUpdateReport>(SendUpdateReport::fromJson(data));
  } else {
    throw std::runtime_error("wrong command variant = " + variant);
  }
  return boost::make_shared<BaseCommand>();
}

Shutdown::Shutdown() { variant = "Shutdown"; }
std::string Shutdown::toJson() { return Json::FastWriter().write(BaseCommand::toJson()); }

GetUpdateRequests::GetUpdateRequests() { variant = "GetUpdateRequests"; }
std::string GetUpdateRequests::toJson() { return Json::FastWriter().write(BaseCommand::toJson()); }

StartDownload::StartDownload(const data::UpdateRequestId& ur_in) : update_request_id(ur_in) {
  variant = "StartDownload";
}

std::string StartDownload::toJson() {
  Json::Value json = BaseCommand::toJson();
  json["fields"].append(update_request_id);
  return Json::FastWriter().write(json);
}

StartDownload StartDownload::fromJson(const std::string& json_str) {
  Json::Reader reader;
  Json::Value json;
  reader.parse(json_str, json);
  return StartDownload(json["fields"][0].asString());
}

AbortDownload::AbortDownload(const data::UpdateRequestId& ur_in) : update_request_id(ur_in) {
  variant = "AbortDownload";
}

std::string AbortDownload::toJson() {
  Json::Value json = BaseCommand::toJson();
  json["fields"].append(update_request_id);
  return Json::FastWriter().write(json);
}

AbortDownload AbortDownload::fromJson(const std::string& json_str) {
  Json::Reader reader;
  Json::Value json;
  reader.parse(json_str, json);
  return AbortDownload(json["fields"][0].asString());
}

SendUpdateReport::SendUpdateReport(const data::UpdateReport& ureport_in) : update_report(ureport_in) {
  variant = "SendUpdateReport";
}

std::string SendUpdateReport::toJson() {
  Json::Value json = BaseCommand::toJson();
  json["fields"].append(update_report.toJson());
  return Json::FastWriter().write(json);
}

SendUpdateReport SendUpdateReport::fromJson(const std::string& json_str) {
  Json::Reader reader;
  Json::Value json;
  reader.parse(json_str, json);

  return SendUpdateReport(data::UpdateReport::fromJson(Json::FastWriter().write(json["fields"][0])));
}

UptaneInstall::UptaneInstall(std::vector<Uptane::Target> packages_in) : packages(packages_in) {
  variant = "UptaneInstall";
}
}  // namespace command
