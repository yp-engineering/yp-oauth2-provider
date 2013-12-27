require 'helper'

class TestOAuth2Provider::TestDriver < Minitest::Test
  include OAuth2Provider::Driver

  def test_default_access_token_path
    assert_match access_token_path,    '/oauth/access_token/'
    assert_match access_token_path,    '/oauth/access_token'
    refute_match access_token_path,    '/oauth/access_token_more'
    refute_match access_token_path, 'pre/oauth/access_token'
  end

  def test_default_access_token_debug_path
    assert_match access_token_debug_path,    '/oauth/access_token_debug/'
    assert_match access_token_debug_path,    '/oauth/access_token_debug'
    refute_match access_token_debug_path,    '/oauth/access_token_debug_more'
    refute_match access_token_debug_path, 'pre/oauth/access_token_debug'
  end

  def test_default_authorize_path
    assert_match authorize_path,    '/oauth/authorize/'
    assert_match authorize_path,    '/oauth/authorize'
    refute_match authorize_path,    '/oauth/authorize_more'
    refute_match authorize_path, 'pre/oauth/authorize'
  end

  def test_default_signer_takes_multiple_arguments
    assert_equal 'token', @@signer.unsign(@@signer.sign('token', 'ignored'))
  end
end
