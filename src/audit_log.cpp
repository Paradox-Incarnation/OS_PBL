#include "audit_log.h"
#include <fstream>
#include <chrono>
#include <iomanip>
#include <sstream>
namespace secureos {
AuditLog::AuditLog(std::filesystem::path dataDir) : file(std::move(dataDir) / "audit.log") { std::filesystem::create_directories(file.parent_path()); }
void AuditLog::record(const std::string& actor, const std::string& event) {
  auto now=std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()); std::tm tm{};
#ifdef _WIN32
  localtime_s(&tm,&now);
#else
  localtime_r(&now,&tm);
#endif
  std::ofstream out(file, std::ios::app); out << std::put_time(&tm, "%F %T") << " | " << actor << " | " << event << "\n";
}
std::vector<std::string> AuditLog::readAll() const { std::vector<std::string> lines; std::ifstream in(file); std::string s; while(std::getline(in,s)) lines.push_back(s); return lines; }
}
