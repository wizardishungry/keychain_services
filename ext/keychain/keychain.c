#include "keychain.h"

VALUE mKeychain;
VALUE eKeychainError;

void keychain_raise_error(OSStatus status)
{
	CFStringRef message = SecCopyErrorMessageString(status, NULL);
	char buf[256];
	char *bytes = CFStringGetCString(message, buf, 256, kCFStringEncodingMacRoman);
	rb_raise(eKeychainError, buf);
}


static VALUE keychain_add_internet_password(VALUE self, VALUE serverNameStr, VALUE securityDomainStr, VALUE accountNameStr, VALUE pathStr, VALUE passwordStr)
{
	OSStatus error;

	SecKeychainRef keychain = NULL;

	char *serverName     = StringValueCStr(serverNameStr);
	char *securityDomain = StringValueCStr(securityDomainStr);
	char *accountName    = StringValueCStr(accountNameStr);
	char *path           = StringValueCStr(pathStr);

	UInt16 port = 0;

	SecProtocolType protocol                 = kSecProtocolTypeAny;
	SecAuthenticationType authenticationType = kSecProtocolTypeAny;

	char *password = StringValueCStr(passwordStr);

	SecKeychainItemRef *itemRef;

	error = SecKeychainAddInternetPassword(
		keychain,
		strlen(serverName), serverName,
		strlen(securityDomain), securityDomain,
		strlen(accountName), accountName,
		strlen(path), path,
		port,
		protocol,
		protocol,
		strlen(password), password,
		&itemRef
	);

	if (error) keychain_raise_error(error);

	VALUE new_keychain_item = rb_obj_alloc(cKeychainItem);
	KEYCHAIN_ITEM(new_keychain_item)->itemRef = itemRef;

	return new_keychain_item;
}

static VALUE keychain_find_internet_password(VALUE self, VALUE serverNameStr, VALUE securityDomainStr, VALUE accountNameStr, VALUE pathStr)
{
	OSStatus error;

	CFTypeRef keychainOrArray = NULL;

	char *serverName     = StringValueCStr(serverNameStr);
	char *securityDomain = StringValueCStr(securityDomainStr);
	char *accountName    = StringValueCStr(accountNameStr);
	char *path           = StringValueCStr(pathStr);

	UInt16 port = 0;

	SecProtocolType protocol                 = kSecProtocolTypeAny;
	SecAuthenticationType authenticationType = kSecProtocolTypeAny;

	SecKeychainItemRef *itemRef;

	error = SecKeychainFindInternetPassword(
		keychainOrArray,
		strlen(serverName), serverName,
		strlen(securityDomain), securityDomain,
		strlen(accountName), accountName,
		strlen(path), path,
		port,
		protocol,
		authenticationType,
		0, NULL,
		&itemRef
	);

	if (error) keychain_raise_error(error);

	VALUE new_keychain_item = rb_obj_alloc(cKeychainItem);
	KEYCHAIN_ITEM(new_keychain_item)->itemRef = itemRef;

	return new_keychain_item;
}

static VALUE keychain_add_generic_password(VALUE self, VALUE serverNameStr, VALUE accountNameStr, VALUE passwordStr)
{
	OSStatus error;

	SecKeychainRef keychain = NULL;

	char *serverName  = StringValueCStr(serverNameStr);
	char *accountName = StringValueCStr(accountNameStr);
	char *password    = StringValueCStr(passwordStr);

	SecKeychainItemRef *itemRef;

	error = SecKeychainAddGenericPassword(
		keychain,
		strlen(serverName), serverName,
		strlen(accountName), accountName,
		strlen(password), password,
		&itemRef
	);

	if (error) keychain_raise_error(error);

	VALUE new_keychain_item = rb_obj_alloc(cKeychainItem);
	KEYCHAIN_ITEM(new_keychain_item)->itemRef = itemRef;

	return new_keychain_item;
}

static VALUE keychain_find_generic_password(VALUE self, VALUE serverNameStr, VALUE accountNameStr)
{
	OSStatus error;

	CFTypeRef keychainOrArray = NULL;

	char *serverName  = StringValueCStr(serverNameStr);
	char *accountName = StringValueCStr(accountNameStr);

	SecKeychainItemRef *itemRef;

	error = SecKeychainFindGenericPassword(
		keychainOrArray,
		strlen(serverName), serverName,
		strlen(accountName), accountName,
		0, NULL,
		&itemRef
	);

	if (error) keychain_raise_error(error);

	VALUE new_keychain_item = rb_obj_alloc(cKeychainItem);
	KEYCHAIN_ITEM(new_keychain_item)->itemRef = itemRef;

	return new_keychain_item;
}

static VALUE keychain_find_items_by_class(VALUE self, SecItemClass itemClass)
{
	OSStatus error;

	CFTypeRef keychainOrArray = NULL;

	SecKeychainItemRef itemRef;
	SecKeychainSearchRef searchRef = NULL;

	error = SecKeychainSearchCreateFromAttributes(keychainOrArray, itemClass, NULL, &searchRef);
	if (error) keychain_raise_error(error);

	VALUE items = rb_ary_new();
	VALUE keychain_item;

	while ((error = SecKeychainSearchCopyNext(searchRef, &itemRef)) == noErr) {
		keychain_item = rb_obj_alloc(cKeychainItem);
		KEYCHAIN_ITEM(keychain_item)->itemRef = itemRef;

		rb_ary_push(items, keychain_item);
	}

	return items;
}

static VALUE keychain_internet_password_items(VALUE self)
{
	return keychain_find_items_by_class(self, kSecInternetPasswordItemClass);
}

static VALUE keychain_generic_password_items(VALUE self)
{
	return keychain_find_items_by_class(self, kSecGenericPasswordItemClass);
}

static VALUE keychain_items(VALUE self)
{
	VALUE items = rb_ary_new();

	rb_funcall(items, rb_intern("concat"), 1, keychain_internet_password_items(self));
	rb_funcall(items, rb_intern("concat"), 1, keychain_generic_password_items(self));

	return items;
}

void Init_keychain()
{
	mKeychain = rb_define_module("Keychain");
	eKeychainError = rb_define_class_under(mKeychain, "Error", rb_eStandardError);

	rb_define_module_function(mKeychain, "add_internet_password", keychain_add_internet_password, 5);
	rb_define_module_function(mKeychain, "find_internet_password", keychain_find_internet_password, 4);
	rb_define_module_function(mKeychain, "add_generic_password", keychain_add_generic_password, 3);
	rb_define_module_function(mKeychain, "find_generic_password", keychain_find_generic_password, 2);

	rb_define_module_function(mKeychain, "internet_password_items", keychain_internet_password_items, 0);
	rb_define_module_function(mKeychain, "generic_password_items", keychain_generic_password_items, 0);
	rb_define_module_function(mKeychain, "items", keychain_items, 0);

	Init_keychain_item();
	Init_keychain_constants();
}
