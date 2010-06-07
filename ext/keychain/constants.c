#include "keychain.h"

#define FourCharCode2String(x)  (char[]) { (x >> 24) & 0xff, (x >> 16) & 0xff, (x >> 8) & 0xff, x & 0xff, 0 }
#define FourCharCode2RString(x) (char[]) { x & 0xff, (x >> 8) & 0xff, (x >> 16) & 0xff, (x >> 24) & 0xff, 0 }

VALUE mProtocol;
VALUE mAuthenticationType;

void Init_keychain_constants()
{
	mAuthenticationType = rb_define_module_under(mKeychain, "AuthenticationType");

	rb_define_const(mAuthenticationType, "NTLM",       rb_str_new2(FourCharCode2RString(kSecAuthenticationTypeNTLM)));
	rb_define_const(mAuthenticationType, "MSN",        rb_str_new2(FourCharCode2RString(kSecAuthenticationTypeMSN)));
	rb_define_const(mAuthenticationType, "DPA",        rb_str_new2(FourCharCode2RString(kSecAuthenticationTypeDPA)));
	rb_define_const(mAuthenticationType, "RPA",        rb_str_new2(FourCharCode2RString(kSecAuthenticationTypeRPA)));
	rb_define_const(mAuthenticationType, "HTTPBasic",  rb_str_new2(FourCharCode2RString(kSecAuthenticationTypeHTTPBasic)));
	rb_define_const(mAuthenticationType, "HTTPDigest", rb_str_new2(FourCharCode2RString(kSecAuthenticationTypeHTTPDigest)));
	rb_define_const(mAuthenticationType, "HTMLForm",   rb_str_new2(FourCharCode2RString(kSecAuthenticationTypeHTMLForm)));
	rb_define_const(mAuthenticationType, "Default",    rb_str_new2(FourCharCode2RString(kSecAuthenticationTypeDefault)));
	rb_define_const(mAuthenticationType, "Any",        rb_str_new2(FourCharCode2RString(kSecAuthenticationTypeAny)));


	mProtocol = rb_define_module_under(mKeychain, "Protocol");

	rb_define_const(mProtocol, "FTP",         rb_str_new2(FourCharCode2String(kSecProtocolTypeFTP)));
	rb_define_const(mProtocol, "FTPAccount",  rb_str_new2(FourCharCode2String(kSecProtocolTypeFTPAccount)));
	rb_define_const(mProtocol, "HTTP",        rb_str_new2(FourCharCode2String(kSecProtocolTypeHTTP)));
	rb_define_const(mProtocol, "IRC",         rb_str_new2(FourCharCode2String(kSecProtocolTypeIRC)));
	rb_define_const(mProtocol, "NNTP",        rb_str_new2(FourCharCode2String(kSecProtocolTypeNNTP)));
	rb_define_const(mProtocol, "POP3",        rb_str_new2(FourCharCode2String(kSecProtocolTypePOP3)));
	rb_define_const(mProtocol, "SMTP",        rb_str_new2(FourCharCode2String(kSecProtocolTypeSMTP)));
	rb_define_const(mProtocol, "SOCKS",       rb_str_new2(FourCharCode2String(kSecProtocolTypeSOCKS)));
	rb_define_const(mProtocol, "IMAP",        rb_str_new2(FourCharCode2String(kSecProtocolTypeIMAP)));
	rb_define_const(mProtocol, "LDAP",        rb_str_new2(FourCharCode2String(kSecProtocolTypeLDAP)));
	rb_define_const(mProtocol, "AppleTalk",   rb_str_new2(FourCharCode2String(kSecProtocolTypeAppleTalk)));
	rb_define_const(mProtocol, "AFP",         rb_str_new2(FourCharCode2String(kSecProtocolTypeAFP)));
	rb_define_const(mProtocol, "Telnet",      rb_str_new2(FourCharCode2String(kSecProtocolTypeTelnet)));
	rb_define_const(mProtocol, "SSH",         rb_str_new2(FourCharCode2String(kSecProtocolTypeSSH)));
	rb_define_const(mProtocol, "FTPS",        rb_str_new2(FourCharCode2String(kSecProtocolTypeFTPS)));
	rb_define_const(mProtocol, "HTTPS",       rb_str_new2(FourCharCode2String(kSecProtocolTypeHTTPS)));
	rb_define_const(mProtocol, "HTTPProxy",   rb_str_new2(FourCharCode2String(kSecProtocolTypeHTTPProxy)));
	rb_define_const(mProtocol, "HTTPSProxy",  rb_str_new2(FourCharCode2String(kSecProtocolTypeHTTPSProxy)));
	rb_define_const(mProtocol, "FTPProxy",    rb_str_new2(FourCharCode2String(kSecProtocolTypeFTPProxy)));
	rb_define_const(mProtocol, "SMB",         rb_str_new2(FourCharCode2String(kSecProtocolTypeSMB)));
	rb_define_const(mProtocol, "RTSP",        rb_str_new2(FourCharCode2String(kSecProtocolTypeRTSP)));
	rb_define_const(mProtocol, "RTSPProxy",   rb_str_new2(FourCharCode2String(kSecProtocolTypeRTSPProxy)));
	rb_define_const(mProtocol, "DAAP",        rb_str_new2(FourCharCode2String(kSecProtocolTypeDAAP)));
	rb_define_const(mProtocol, "EPPC",        rb_str_new2(FourCharCode2String(kSecProtocolTypeEPPC)));
	rb_define_const(mProtocol, "IPP",         rb_str_new2(FourCharCode2String(kSecProtocolTypeIPP)));
	rb_define_const(mProtocol, "NNTPS",       rb_str_new2(FourCharCode2String(kSecProtocolTypeNNTPS)));
	rb_define_const(mProtocol, "LDAPS",       rb_str_new2(FourCharCode2String(kSecProtocolTypeLDAPS)));
	rb_define_const(mProtocol, "TelnetS",     rb_str_new2(FourCharCode2String(kSecProtocolTypeTelnetS)));
	rb_define_const(mProtocol, "IMAPS",       rb_str_new2(FourCharCode2String(kSecProtocolTypeIMAPS)));
	rb_define_const(mProtocol, "IRCS",        rb_str_new2(FourCharCode2String(kSecProtocolTypeIRCS)));
	rb_define_const(mProtocol, "POP3S",       rb_str_new2(FourCharCode2String(kSecProtocolTypePOP3S)));
}
