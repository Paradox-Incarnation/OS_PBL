#pragma once
#include "common.h"
#include <filesystem>
#include <string>
namespace secureos { class AuditLog;
class EncryptionService { std::filesystem::path root; AuditLog& log; public:
 EncryptionService(std::filesystem::path dataDir,AuditLog& audit);
 bool encrypt(const User&,const std::string&,const std::string& output,std::string& keyHex,std::string& message);
 bool decrypt(const User&,const std::string&,const std::string& output,const std::string& keyHex,std::string& message);
}; }
