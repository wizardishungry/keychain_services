require 'mkmf'

$LDFLAGS = '-framework Security'
dir_config 'keychain'
create_makefile 'keychain'
