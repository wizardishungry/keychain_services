#include "keychain.h"

#define FourCharCode2String(x)  (char[]) { (x >> 24) & 0xff, (x >> 16) & 0xff, (x >> 8) & 0xff, x & 0xff, 0 }
#define FourCharCode2RString(x) (char[]) { x & 0xff, (x >> 8) & 0xff, (x >> 16) & 0xff, (x >> 24) & 0xff, 0 }

VALUE mProtocol;
VALUE mAuthenticationType;

void Init_keychain_constants()
{
	mAuthenticationType = rb_define_module_under(mKeychain, "AuthenticationType");

	rb_define_const(mAuthenticationType, "NTLM",       KEYCHAIN_BINARY_STR_NEW2(FourCharCode2RString(kSecAuthenticationTypeNTLM)));
	rb_define_const(mAuthenticationType, "MSN",        KEYCHAIN_BINARY_STR_NEW2(FourCharCode2RString(kSecAuthenticationTypeMSN)));
	rb_define_const(mAuthenticationType, "DPA",        KEYCHAIN_BINARY_STR_NEW2(FourCharCode2RString(kSecAuthenticationTypeDPA)));
	rb_define_const(mAuthenticationType, "RPA",        KEYCHAIN_BINARY_STR_NEW2(FourCharCode2RString(kSecAuthenticationTypeRPA)));
	rb_define_const(mAuthenticationType, "HTTPBasic",  KEYCHAIN_BINARY_STR_NEW2(FourCharCode2RString(kSecAuthenticationTypeHTTPBasic)));
	rb_define_const(mAuthenticationType, "HTTPDigest", KEYCHAIN_BINARY_STR_NEW2(FourCharCode2RString(kSecAuthenticationTypeHTTPDigest)));
	rb_define_const(mAuthenticationType, "HTMLForm",   KEYCHAIN_BINARY_STR_NEW2(FourCharCode2RString(kSecAuthenticationTypeHTMLForm)));
	rb_define_const(mAuthenticationType, "Default",    KEYCHAIN_BINARY_STR_NEW2(FourCharCode2RString(kSecAuthenticationTypeDefault)));
	rb_define_const(mAuthenticationType, "Any",        KEYCHAIN_BINARY_STR_NEW2(FourCharCode2RString(kSecAuthenticationTypeAny)));


	mProtocol = rb_define_module_under(mKeychain, "Protocol");

	rb_define_const(mProtocol, "FTP",         KEYCHAIN_BINARY_STR_NEW2(FourCharCode2String(kSecProtocolTypeFTP)));
	rb_define_const(mProtocol, "FTPAccount",  KEYCHAIN_BINARY_STR_NEW2(FourCharCode2String(kSecProtocolTypeFTPAccount)));
	rb_define_const(mProtocol, "HTTP",        KEYCHAIN_BINARY_STR_NEW2(FourCharCode2String(kSecProtocolTypeHTTP)));
	rb_define_const(mProtocol, "IRC",         KEYCHAIN_BINARY_STR_NEW2(FourCharCode2String(kSecProtocolTypeIRC)));
	rb_define_const(mProtocol, "NNTP",        KEYCHAIN_BINARY_STR_NEW2(FourCharCode2String(kSecProtocolTypeNNTP)));
	rb_define_const(mProtocol, "POP3",        KEYCHAIN_BINARY_STR_NEW2(FourCharCode2String(kSecProtocolTypePOP3)));
	rb_define_const(mProtocol, "SMTP",        KEYCHAIN_BINARY_STR_NEW2(FourCharCode2String(kSecProtocolTypeSMTP)));
	rb_define_const(mProtocol, "SOCKS",       KEYCHAIN_BINARY_STR_NEW2(FourCharCode2String(kSecProtocolTypeSOCKS)));
	rb_define_const(mProtocol, "IMAP",        KEYCHAIN_BINARY_STR_NEW2(FourCharCode2String(kSecProtocolTypeIMAP)));
	rb_define_const(mProtocol, "LDAP",        KEYCHAIN_BINARY_STR_NEW2(FourCharCode2String(kSecProtocolTypeLDAP)));
	rb_define_const(mProtocol, "AppleTalk",   KEYCHAIN_BINARY_STR_NEW2(FourCharCode2String(kSecProtocolTypeAppleTalk)));
	rb_define_const(mProtocol, "AFP",         KEYCHAIN_BINARY_STR_NEW2(FourCharCode2String(kSecProtocolTypeAFP)));
	rb_define_const(mProtocol, "Telnet",      KEYCHAIN_BINARY_STR_NEW2(FourCharCode2String(kSecProtocolTypeTelnet)));
	rb_define_const(mProtocol, "SSH",         KEYCHAIN_BINARY_STR_NEW2(FourCharCode2String(kSecProtocolTypeSSH)));
	rb_define_const(mProtocol, "FTPS",        KEYCHAIN_BINARY_STR_NEW2(FourCharCode2String(kSecProtocolTypeFTPS)));
	rb_define_const(mProtocol, "HTTPS",       KEYCHAIN_BINARY_STR_NEW2(FourCharCode2String(kSecProtocolTypeHTTPS)));
	rb_define_const(mProtocol, "HTTPProxy",   KEYCHAIN_BINARY_STR_NEW2(FourCharCode2String(kSecProtocolTypeHTTPProxy)));
	rb_define_const(mProtocol, "HTTPSProxy",  KEYCHAIN_BINARY_STR_NEW2(FourCharCode2String(kSecProtocolTypeHTTPSProxy)));
	rb_define_const(mProtocol, "FTPProxy",    KEYCHAIN_BINARY_STR_NEW2(FourCharCode2String(kSecProtocolTypeFTPProxy)));
	rb_define_const(mProtocol, "SMB",         KEYCHAIN_BINARY_STR_NEW2(FourCharCode2String(kSecProtocolTypeSMB)));
	rb_define_const(mProtocol, "RTSP",        KEYCHAIN_BINARY_STR_NEW2(FourCharCode2String(kSecProtocolTypeRTSP)));
	rb_define_const(mProtocol, "RTSPProxy",   KEYCHAIN_BINARY_STR_NEW2(FourCharCode2String(kSecProtocolTypeRTSPProxy)));
	rb_define_const(mProtocol, "DAAP",        KEYCHAIN_BINARY_STR_NEW2(FourCharCode2String(kSecProtocolTypeDAAP)));
	rb_define_const(mProtocol, "EPPC",        KEYCHAIN_BINARY_STR_NEW2(FourCharCode2String(kSecProtocolTypeEPPC)));
	rb_define_const(mProtocol, "IPP",         KEYCHAIN_BINARY_STR_NEW2(FourCharCode2String(kSecProtocolTypeIPP)));
	rb_define_const(mProtocol, "NNTPS",       KEYCHAIN_BINARY_STR_NEW2(FourCharCode2String(kSecProtocolTypeNNTPS)));
	rb_define_const(mProtocol, "LDAPS",       KEYCHAIN_BINARY_STR_NEW2(FourCharCode2String(kSecProtocolTypeLDAPS)));
	rb_define_const(mProtocol, "TelnetS",     KEYCHAIN_BINARY_STR_NEW2(FourCharCode2String(kSecProtocolTypeTelnetS)));
	rb_define_const(mProtocol, "IMAPS",       KEYCHAIN_BINARY_STR_NEW2(FourCharCode2String(kSecProtocolTypeIMAPS)));
	rb_define_const(mProtocol, "IRCS",        KEYCHAIN_BINARY_STR_NEW2(FourCharCode2String(kSecProtocolTypeIRCS)));
	rb_define_const(mProtocol, "POP3S",       KEYCHAIN_BINARY_STR_NEW2(FourCharCode2String(kSecProtocolTypePOP3S)));
}
