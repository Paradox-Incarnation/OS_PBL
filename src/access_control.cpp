#include "access_control.h"
namespace secureos {
bool allowed(Role role, Action action) {
  if (role == Role::Admin) return true;
  if (role == Role::Editor)
    return action == Action::Read || action == Action::Create || action == Action::Edit || action == Action::Encrypt || action == Action::Decrypt || action == Action::ViewLogs;
  return action == Action::Read;
}
}
