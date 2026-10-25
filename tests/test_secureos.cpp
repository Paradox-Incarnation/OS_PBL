#include "auth.h"
#include "audit_log.h"
#include "file_manager.h"
#include "encryption.h"
#include <filesystem>
#include <fstream>
#include <iostream>
using namespace secureos;
static int failed=0;
static void check(bool value,const char* name){if(!value){++failed;std::cerr<<"FAIL: "<<name<<"\n";}}
int main(){
  auto data=std::filesystem::temp_directory_path()/"secureos_test_run";std::filesystem::remove_all(data);
  AuditLog log(data);AuthService auth(data,log);FileManager files(data,log);EncryptionService crypto(data,log);std::string message,key,text;
  check(auth.registerUser("admin","long-password-1",message),"register admin");
  check(auth.allUsers()[0].role==Role::Admin,"first account is admin");
  check(!auth.login("admin","wrong-password",message),"bad login rejected");
  auto admin=auth.login("admin","long-password-1",message);check(bool(admin),"good login");
  check(auth.changePassword("admin","long-password-1","long-password-2",message),"password change");
  check(!auth.login("admin","long-password-1",message),"old password rejected");
  admin=auth.login("admin","long-password-2",message);
  check(auth.registerUser("viewer","another-long-password",message),"register viewer");
  auto viewer=auth.login("viewer","another-long-password",message);check(bool(viewer),"viewer login");
  check(!files.create(*viewer,"no.txt","x",message),"viewer cannot create");
  check(files.create(*admin,"note.txt","secret text",message),"admin creates");
  check(!files.read(*admin,"../users.db",text,message),"path traversal rejected");
  check(!auth.setRole(*viewer,"viewer",Role::Admin,message),"unauthorized role change rejected");
  check(crypto.encrypt(*admin,"note.txt","encrypted.sos",key,message),"encrypt");
  check(!crypto.decrypt(*admin,"encrypted.sos","bad.txt",std::string(64,'0'),message),"wrong key fails");
  std::filesystem::copy_file(data/"files"/"encrypted.sos",data/"files"/"tampered.sos");
  { std::fstream file(data/"files"/"tampered.sos",std::ios::in|std::ios::out|std::ios::binary);file.seekp(-1,std::ios::end);file.put('X'); }
  check(!crypto.decrypt(*admin,"tampered.sos","tampered-out.txt",key,message),"tampered ciphertext rejected");
  check(crypto.decrypt(*admin,"encrypted.sos","restored.txt",key,message),"decrypt");
  check(files.read(*admin,"restored.txt",text,message)&&text=="secret text","round trip");
  auto events=log.readAll();check(!events.empty(),"audit logs exist");for(auto& event:events)check(event.find("long-password")==std::string::npos,"logs expose no password");
  std::filesystem::remove_all(data);if(failed){std::cerr<<failed<<" test(s) failed\n";return 1;}std::cout<<"All SecureOS tests passed.\n";
}
