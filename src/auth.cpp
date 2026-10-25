#include "auth.h"
#include "audit_log.h"
#include "access_control.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <fstream>
#include <sstream>
#include <iomanip>
namespace secureos {
static std::string hex(const std::vector<unsigned char>& v) { std::ostringstream o; for(auto b:v)o<<std::hex<<std::setw(2)<<std::setfill('0')<<(int)b; return o.str(); }
static std::vector<unsigned char> unhex(const std::string& s) { std::vector<unsigned char> v; if(s.size()%2)return v; for(size_t i=0;i<s.size();i+=2){ unsigned int x; std::istringstream(s.substr(i,2))>>std::hex>>x; v.push_back((unsigned char)x); } return v; }
static bool derive(const std::string& password,const std::vector<unsigned char>& salt,std::vector<unsigned char>& result) {
  result.resize(32); return EVP_PBE_scrypt(password.data(),password.size(),salt.data(),salt.size(),1<<15,8,1,64*1024*1024,result.data(),result.size()) == 1;
}
AuthService::AuthService(std::filesystem::path dataDir, AuditLog& audit) : database(std::move(dataDir)/"users.db"),log(audit) {
 std::filesystem::create_directories(database.parent_path()); std::ifstream in(database); std::string line;
 while(std::getline(in,line)){std::istringstream s(line);std::string n,r,sa,h; if(std::getline(s,n,'|')&&std::getline(s,r,'|')&&std::getline(s,sa,'|')&&std::getline(s,h)){ auto salt=unhex(sa), hash=unhex(h); if(!n.empty()&&salt.size()==16&&hash.size()==32) users.push_back({n,r=="Admin"?Role::Admin:r=="Editor"?Role::Editor:Role::Viewer,salt,hash}); }}
}
void AuthService::save() const { std::ofstream out(database,std::ios::trunc); for(const auto& u:users)out<<u.name<<'|'<<roleName(u.role)<<'|'<<hex(u.salt)<<'|'<<hex(u.passwordHash)<<'\n'; }
bool AuthService::registerUser(const std::string& n,const std::string& p,std::string& msg) {
 if(n.size()<3||n.size()>32||!isSafeName(n)){msg="Username must be 3-32 letters/numbers (no paths).";return false;} if(p.size()<10){msg="Password must contain at least 10 characters.";return false;} for(auto&u:users)if(u.name==n){msg="That username already exists.";return false;}
 User u{n,users.empty()?Role::Admin:Role::Viewer,std::vector<unsigned char>(16),{}}; if(RAND_bytes(u.salt.data(),(int)u.salt.size())!=1||!derive(p,u.salt,u.passwordHash)){msg="Secure password setup failed.";return false;} users.push_back(u);save();log.record(n,"registered as "+roleName(u.role));msg= u.role==Role::Admin ? "First account created as Admin." : "Account created as Viewer; an Admin can change its role.";return true;
}
std::optional<User> AuthService::login(const std::string& n,const std::string& p,std::string& msg) {
 if(failures[n]>=5){msg="Too many failed attempts. Restart the program before trying again.";log.record(n,"login denied: rate limit");return {};} for(const auto&u:users)if(u.name==n){std::vector<unsigned char> h; if(derive(p,u.salt,h)&&CRYPTO_memcmp(h.data(),u.passwordHash.data(),h.size())==0){failures.erase(n);log.record(n,"login successful");msg="Welcome.";return u;}}
 ++failures[n];log.record(n,"login failed");msg="Invalid username or password.";return {};
}
bool AuthService::changePassword(const std::string& n,const std::string& old,const std::string& fresh,std::string& msg) { auto maybe=login(n,old,msg);if(!maybe)return false;if(fresh.size()<10){msg="New password must be at least 10 characters.";return false;}for(auto&u:users)if(u.name==n){RAND_bytes(u.salt.data(),(int)u.salt.size());if(!derive(fresh,u.salt,u.passwordHash)){msg="Password update failed.";return false;}save();log.record(n,"password changed");msg="Password changed.";return true;}return false; }
bool AuthService::setRole(const User& actor,const std::string& target,Role role,std::string& msg) { if(!allowed(actor.role,Action::ManageUsers)){log.record(actor.name,"denied user role change");msg="Access denied.";return false;} if(target==actor.name){msg="You cannot change your own role.";return false;}for(auto&u:users)if(u.name==target){u.role=role;save();log.record(actor.name,"changed "+target+" role to "+roleName(role));msg="Role updated.";return true;}msg="User not found.";return false; }
}
