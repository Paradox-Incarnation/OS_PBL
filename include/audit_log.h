#pragma once
#include <filesystem>
#include <string>
#include <vector>
namespace secureos {
class AuditLog {
  std::filesystem::path file;
public:
  explicit AuditLog(std::filesystem::path dataDir);
  void record(const std::string& actor, const std::string& event);
  std::vector<std::string> readAll() const;
}; }
