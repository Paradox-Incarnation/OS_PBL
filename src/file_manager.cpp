#include "file_manager.h"
#include "audit_log.h"
#include "access_control.h"
#include <fstream>
#include <sstream>
namespace secureos {
FileManager::FileManager(std::filesystem::path dataDir,AuditLog& audit):root(dataDir/"files"),ownership(dataDir/"file_owners.db"),log(audit){std::filesystem::create_directories(root);std::ifstream in(ownership);std::string line;while(std::getline(in,line)){auto p=line.find('|');if(p!=std::string::npos)owners[line.substr(0,p)]=line.substr(p+1);}}
void FileManager::saveOwners()const{std::ofstream out(ownership,std::ios::trunc);for(const auto& item:owners)out<<item.first<<'|'<<item.second<<'\n';}
std::filesystem::path FileManager::checkedPath(const std::string& n)const {if(!isSafeName(n))return {};return root/n;}
bool FileManager::authorize(const User&u,Action a,const std::string& n,std::string&m)const {if(checkedPath(n).empty()){m="Unsafe filename rejected.";return false;}if(!allowed(u.role,a)){m="Access denied for your role.";return false;}return true;}
std::vector<std::string> FileManager::list()const{std::vector<std::string>r;for(auto&e:std::filesystem::directory_iterator(root))if(e.is_regular_file())r.push_back(e.path().filename().string());return r;}
std::string FileManager::ownerOf(const std::string& name)const{auto it=owners.find(name);return it==owners.end()?"unknown (imported/encrypted file)":it->second;}
bool FileManager::create(const User&u,const std::string&n,const std::string&text,std::string&m){if(!authorize(u,Action::Create,n,m)){log.record(u.name,"denied create "+n);return false;}auto p=checkedPath(n);if(std::filesystem::exists(p)){m="File already exists.";return false;}std::ofstream o(p);if(!o){m="Could not create file.";return false;}o<<text;owners[n]=u.name;saveOwners();log.record(u.name,"created file "+n);m="File created.";return true;}
bool FileManager::read(const User&u,const std::string&n,std::string&text,std::string&m){if(!authorize(u,Action::Read,n,m)){log.record(u.name,"denied read "+n);return false;}std::ifstream i(checkedPath(n));if(!i){m="File not found.";return false;}std::ostringstream o;o<<i.rdbuf();text=o.str();log.record(u.name,"read file "+n);return true;}
bool FileManager::edit(const User&u,const std::string&n,const std::string&text,std::string&m){if(!authorize(u,Action::Edit,n,m)){log.record(u.name,"denied edit "+n);return false;}std::ofstream o(checkedPath(n),std::ios::trunc);if(!o){m="File not found or cannot be written.";return false;}o<<text;log.record(u.name,"modified file "+n);m="File saved.";return true;}
bool FileManager::remove(const User&u,const std::string&n,std::string&m){if(!authorize(u,Action::DeleteFile,n,m)){log.record(u.name,"denied delete "+n);return false;}if(!std::filesystem::remove(checkedPath(n))){m="File not found.";return false;}owners.erase(n);saveOwners();log.record(u.name,"deleted file "+n);m="File deleted.";return true;}
}
