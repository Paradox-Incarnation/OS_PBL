#pragma once
#include "common.h"
#include <filesystem>
#include <string>
#include <unordered_map>
#include <vector>
namespace secureos { class AuditLog;
class FileManager {
  std::filesystem::path root, ownership; AuditLog& log; std::unordered_map<std::string,std::string> owners;
  void saveOwners() const;
  std::filesystem::path checkedPath(const std::string&) const;
  bool authorize(const User&,Action,const std::string&,std::string&) const;
public:
  FileManager(std::filesystem::path dataDir, AuditLog& audit);
  std::vector<std::string> list() const;
  std::string ownerOf(const std::string&) const;
  bool create(const User&,const std::string&,const std::string&,std::string&);
  bool read(const User&,const std::string&,std::string&,std::string&);
  bool edit(const User&,const std::string&,const std::string&,std::string&);
  bool remove(const User&,const std::string&,std::string&);
  std::filesystem::path pathFor(const std::string&) const { return checkedPath(std::string()); }
  std::filesystem::path rootPath() const { return root; }
}; }
