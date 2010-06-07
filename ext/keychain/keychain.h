#include "ruby.h"
#include <Security/Security.h>

extern VALUE mKeychain, cKeychainItem;
extern VALUE eKeychainError;

void keychain_raise_error(OSStatus status);

void Init_keychain_item();
void Init_keychain_constants();

#define KEYCHAIN_ITEM(obj) (Check_Type(obj, T_DATA), (struct KeychainItem*)DATA_PTR(obj))

struct KeychainItem {
	SecKeychainItemRef *itemRef;
};
