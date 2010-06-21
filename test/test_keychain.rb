require 'test/unit'
require 'keychain'

require 'json'
require 'yaml'

class TestKeychain < Test::Unit::TestCase
  def test_internet_password
    old_length = Keychain.internet_password_items.length
    item = Keychain.add_internet_password('example.org', '', 'josh', '', 'secret')
    assert item
    assert_equal old_length + 1, Keychain.internet_password_items.length

    assert item.creation_date
    assert item.modified_date
    assert_equal '', item.comment
    assert_equal 'lpaa', item.creator
    assert_equal '', item.type
    assert_equal 'example.org', item.label
    assert_equal 'josh', item.account
    assert_equal 'example.org', item.server
    assert_equal nil, item.authentication_type
    assert_equal 0, item.port
    assert_equal '', item.path
    assert_equal nil, item.protocol
    assert_equal 'secret', item.password

    assert item.to_json
    assert item.to_yaml

    item = Keychain.find_internet_password('example.org', '', 'josh', '')
    assert item
    assert_equal 'secret', item.password
  ensure
    item.delete if item
  end

  def test_generic_password
    old_length = Keychain.generic_password_items.length
    item = Keychain.add_generic_password('', 'linksys', 'password')
    assert item
    assert_equal old_length + 1, Keychain.generic_password_items.length

    assert item.creation_date
    assert item.modified_date
    assert_equal '', item.kind
    assert_equal '', item.comment
    assert_equal '', item.type
    assert_equal 'linksys', item.label
    assert_equal 'linksys', item.account
    assert_equal '', item.service
    assert_equal '', item.value
    assert_equal 'password', item.password

    assert item.to_json
    assert item.to_yaml

    item = Keychain.find_generic_password('', 'linksys')
    assert item
    assert_equal 'password', item.password
  ensure
    item.delete if item
  end
end
