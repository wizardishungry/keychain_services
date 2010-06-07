require 'mkmf'

$LDFLAGS = '-framework Security'
create_makefile 'keychain'
