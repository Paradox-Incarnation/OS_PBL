#include <filesystem>
#include <iostream>
namespace secureos { void runUI(const std::filesystem::path&); }
int main(){try{secureos::runUI("data");}catch(const std::exception&e){std::cerr<<"SecureOS error: "<<e.what()<<"\n";return 1;}return 0;}
