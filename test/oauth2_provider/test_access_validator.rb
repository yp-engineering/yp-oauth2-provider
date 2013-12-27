require 'helper'

class TestOAuth2Provider::TestAccessValidator < Minitest::Test
  include Rack::Test::Methods

  def setup
    @owner  = Owner.new(1, 'user@example.com', 'password')
    @client = Client.new('testcid', 'clientsecret', ['all'],
                         'http://example.com/callback')
    @app = lambda do |env|
      env['oauth2-provider.validator'].verify!('provided')
      [200, {}, ['response body']]
    end

    # quiet warnings
    current_session.instance_variable_set :@digest_username, nil
  end

  def teardown
    Owner::Store.clear
    Client::Store.clear
  end

  def app
    Rack::Session::Cookie.new(
      OAuth2Provider::Main.new(@app, DummyDriver),
      secret: 'secret')
  end

  def test_without_authorization_header
    get "/"

    assert_equal 401, last_response.status
    assert_equal "Bearer realm=\"#{DummyDriver.realm}\"", last_response.headers["WWW-Authenticate"]
  end

  def test_with_invalid_token_on_header
    header('Authorization', "Bearer invalid.token")
    get "/"

    assert_equal 401, last_response.status
    assert_equal "Bearer realm=\"#{DummyDriver.realm}\", error=\"invalid_token\", error_description=\"Invalid token\"", last_response.headers["WWW-Authenticate"]
  end

  def test_with_insufficient_scope
    token = OAuth2Provider::Tokens::Bearer.new(@client, @owner, ["notprovided"],
                                               signer: Signer)
    header('Authorization', "Bearer #{token.access_token}")
    get "/"

    assert_equal 403, last_response.status
    assert_equal "Bearer realm=\"#{DummyDriver.realm}\", error=\"insufficient_scope\", error_description=\"Insufficient scope\", scope=\"provided\"", last_response.headers["WWW-Authenticate"]
  end

  def test_with_sufficient_scope
    token = OAuth2Provider::Tokens::Bearer.new(@client, @owner, ["provided"],
                                               signer: Signer)
    header('Authorization', "Bearer #{token.access_token}")
    get "/"

    assert_equal 200, last_response.status
  end

  def test_with_expired_token
    token = OAuth2Provider::Tokens::Bearer.new(@client, @owner, ["provided"],
                                               signer: Signer)
    token.expires_in = 1
    token.created_at = Time.now.utc - 1000
    header('Authorization', "Bearer #{token.access_token}")
    get "/"

    assert_equal 401, last_response.status
    assert_equal "Bearer realm=\"Example.com\", error=\"invalid_token\", error_description=\"Invalid token\"", last_response.headers["WWW-Authenticate"]
  end
end
