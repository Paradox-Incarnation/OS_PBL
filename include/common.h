#pragma once
#include <string>
#include <vector>
#include <filesystem>

namespace secureos {
enum class Role { Admin, Editor, Viewer };
enum class Action { Read, Create, Edit, DeleteFile, Encrypt, Decrypt, ManageUsers, ViewLogs };
struct User { std::string name; Role role; std::vector<unsigned char> salt, passwordHash; };
inline std::string roleName(Role r) { return r == Role::Admin ? "Admin" : r == Role::Editor ? "Editor" : "Viewer"; }
inline bool isSafeName(const std::string& name) {
  std::filesystem::path p(name);
  return !name.empty() && p.filename() == p && !p.is_absolute() && name.find("..") == std::string::npos && name.find_first_of("\\/") == std::string::npos;
}
}
