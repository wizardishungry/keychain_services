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

#ifdef HAVE_RUBY_ENCODING_H
#include <ruby/encoding.h>

#define KEYCHAIN_ASCII_STR_NEW(str, len)  rb_usascii_str_new((str), (len))
#define KEYCHAIN_UTF8_STR_NEW(str, len)   rb_enc_str_new((str), (len), rb_utf8_encoding())
#define KEYCHAIN_BINARY_STR_NEW(str, len) rb_enc_str_new((str), (len), rb_ascii8bit_encoding())

#define KEYCHAIN_ASCII_STR_NEW2(str)  rb_usascii_str_new2((str))
#define KEYCHAIN_UTF8_STR_NEW2(str)   rb_enc_str_new((str), strlen((str)), rb_utf8_encoding())
#define KEYCHAIN_BINARY_STR_NEW2(str) rb_enc_str_new((str), strlen((str)), rb_ascii8bit_encoding())

#define KEYCHAIN_SET_ASCII_ENCODING(str) \
	do { \
		if ((str) != Qnil) { \
			ENCODING_SET((str), rb_usascii_encindex()); \
		} \
	} while (0)
#define KEYCHAIN_SET_UTF8_ENCODING(str) \
	do { \
		if ((str) != Qnil) { \
			ENCODING_SET((str), rb_utf8_encindex()); \
		} \
	} while (0)
#define KEYCHAIN_SET_BINARY_ENCODING(str) \
do { \
	if ((str) != Qnil) { \
		ENCODING_SET((str), rb_ascii8bit_encindex()); \
	} \
} while (0)

#else

#define KEYCHAIN_ASCII_STR_NEW(str, len)  rb_str_new((str), (len))
#define KEYCHAIN_UTF8_STR_NEW(str, len)   rb_str_new((str), (len))
#define KEYCHAIN_BINARY_STR_NEW(str, len) rb_str_new((str), (len))

#define KEYCHAIN_ASCII_STR_NEW2(str)  rb_str_new2((str))
#define KEYCHAIN_UTF8_STR_NEW2(str)   rb_str_new((str), strlen((s)))
#define KEYCHAIN_BINARY_STR_NEW2(str) rb_str_new((str), strlen((s)))

#define KEYCHAIN_SET_ASCII_ENCODING(str) /* empty */
#define KEYCHAIN_SET_UTF8_ENCODING(str) /* empty */
#define KEYCHAIN_SET_BINARY_ENCODING(str) /* empty */

#endif
