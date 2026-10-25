#pragma once
#include "common.h"
#include <filesystem>
#include <optional>
#include <unordered_map>
namespace secureos {
class AuditLog;
class AuthService {
  std::filesystem::path database; AuditLog& log; std::vector<User> users; std::unordered_map<std::string,int> failures;
  void save() const;
public:
  AuthService(std::filesystem::path dataDir, AuditLog& audit);
  bool registerUser(const std::string&, const std::string&, std::string&); // first account is Admin
  std::optional<User> login(const std::string&, const std::string&, std::string&);
  bool changePassword(const std::string&, const std::string&, const std::string&, std::string&);
  bool setRole(const User&, const std::string&, Role, std::string&);
  const std::vector<User>& allUsers() const { return users; }
}; }
