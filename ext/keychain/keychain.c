#include "keychain.h"

VALUE mKeychain;
VALUE eKeychainError;

void keychain_raise_error(OSStatus status)
{
	char *message;

	switch (status) {
		case errSecUnimplemented:
			message = "Function or operation not implemented";
			break;
		case errSecParam:
			message = "One or more parameters passed to the function were not valid";
			break;
		case errSecAllocate:
			message = "Failed to allocate memory";
			break;
		case errSecNotAvailable:
			message = "No trust results are available";
			break;
		case errSecReadOnly:
			message = "Read only error";
			break;
		case errSecAuthFailed:
			message = "Authorization/Authentication failed";
			break;
		case errSecNoSuchKeychain:
			message = "The keychain does not exist";
			break;
		case errSecInvalidKeychain:
			message = "The keychain is not valid";
			break;
		case errSecDuplicateKeychain:
			message = "A keychain with the same name already exists";
			break;
		case errSecDuplicateCallback:
			message = "More than one callback of the same name exists";
			break;
		case errSecInvalidCallback:
			message = "The callback is not valid";
			break;
		case errSecDuplicateItem:
			message = "The item already exists";
			break;
		case errSecItemNotFound:
			message = "The item cannot be found";
			break;
		case errSecBufferTooSmall:
			message = "The buffer is too small";
			break;
		case errSecDataTooLarge:
			message = "The data is too large for the particular data type";
			break;
		case errSecNoSuchAttr:
			message = "The attribute does not exist";
			break;
		case errSecInvalidItemRef:
			message = "The item reference is invalid";
			break;
		case errSecInvalidSearchRef:
			message = "The search reference is invalid";
			break;
		case errSecNoSuchClass:
			message = "The keychain item class does not exist";
			break;
		case errSecNoDefaultKeychain:
			message = "A default keychain does not exist";
			break;
		case errSecInteractionNotAllowed:
			message = "Interaction with the Security Server is not allowed";
			break;
		case errSecReadOnlyAttr:
			message = "The attribute is read only";
			break;
		case errSecWrongSecVersion:
			message = "The version is incorrect";
			break;
		case errSecKeySizeNotAllowed:
			message = "The key size is not allowed";
			break;
		case errSecNoStorageModule:
			message = "There is no storage module available";
			break;
		case errSecNoCertificateModule:
			message = "There is no certificate module available";
			break;
		case errSecNoPolicyModule:
			message = "There is no policy module available";
			break;
		case errSecInteractionRequired:
			message = "User interaction is required";
			break;
		case errSecDataNotAvailable:
			message = "The data is not available";
			break;
		case errSecDataNotModifiable:
			message = "The data is not modifiable";
			break;
		case errSecCreateChainFailed:
			message = "The attempt to create a certificate chain failed";
			break;
		case errSecInvalidPrefsDomain:
			message = "The preference domain specified is invalid";
			break;
		case errSecACLNotSimple:
			message = "The access control list is not in standard simple form";
			break;
		case errSecPolicyNotFound:
			message = "The policy specified cannot be found";
			break;
		case errSecInvalidTrustSetting:
			message = "The trust setting is invalid";
			break;
		case errSecNoAccessForItem:
			message = "The specified item has no access control";
			break;
		case errSecInvalidOwnerEdit:
			message = "An invalid attempt to change the owner of an item";
			break;
		case errSecTrustNotAvailable:
			message = "No trust results are available";
			break;
		case errSecUnsupportedFormat:
			message = "The specified import or export format is not supported";
			break;
		case errSecUnknownFormat:
			message = "The item you are trying to import has an unknown format";
			break;
		case errSecKeyIsSensitive:
			message = "The key must be wrapped to be exported";
			break;
		case errSecMultiplePrivKeys:
			message = "An attempt was made to import multiple private keys";
			break;
		case errSecPassphraseRequired:
			message = "A password is required for import or export";
			break;
		case errSecInvalidPasswordRef:
			message = "The password reference was invalid";
			break;
		case errSecInvalidTrustSettings:
			message = "The trust settings record was corrupted";
			break;
		case errSecNoTrustSettings:
			message = "No trust settings were found";
			break;
		case errSecPkcs12VerifyFailure:
			message = "MAC verification failed during PKCS12 Import";
			break;
		case errSecDecode:
			message = "Unable to decode the provided data";
			break;
		default:
			message = "Unknown error";
	}

	rb_raise(eKeychainError, message);
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
