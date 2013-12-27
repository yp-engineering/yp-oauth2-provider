require 'helper'

class TestOAuth2Provider
  include Rack::Test::Methods

  def setup
    @owner  = Owner.new(1, 'user@example.com', 'password')
    @client = Client.new('testcid', 'clientsecret', ['all'],
                         'http://example.com/callback')
    @code = Code.new('valid', 'all', @owner.id, @client.client_id,
                     @client.redirect_uri)
    @code_no_uri = Code.new('valid-2', 'all', @owner.id, @client.client_id,
                            nil)

    # quiet warnings
    current_session.instance_variable_set :@digest_username, nil
  end

  def teardown
    Owner::Store.clear
    Client::Store.clear
    Code::Store.clear
  end

  def app
    Rack::Session::Cookie.new(
      OAuth2Provider::Main.new(App, DummyDriver),
      secret: 'secret')
  end

  def test_authorization_response_shown
    get "/oauth/authorize", {
      client_id: 'testcid',
      response_type: 'code',
      scope: 'all'
    }

    assert_equal 200, last_response.status
    assert_equal "Authorization dialog form", last_response.body
  end

  def test_authorization_redirects_on_error
    get "/oauth/authorize", {
      client_id: 'testcid',
      response_type: 'invalid',
      scope: 'all'
    }

    cb_uri = 'http://example.com/callback?error=unsupported_grant_type&error_description=Unsupported+grant+type%3A+invalid+response+type+%27invalid%27'

    assert_equal 302, last_response.status
    assert_equal cb_uri, last_response.headers['Location']
  end

  def test_authorization_invalid_client_response
    get "/oauth/authorize", {
      client_id: 'invalid-client',
      response_type: 'code',
      scope: 'all'
    }

    assert_equal 400, last_response.status
    assert_equal "Invalid client", last_response.body
  end

  def test_authorization_redirect_uri_with_extra_params
    get "/oauth/authorize", {
      client_id: 'testcid',
      response_type: 'code',
      scope: 'all',
      redirect_uri: 'http://example.com/callback?extra=a'
    }

    assert_equal 200, last_response.status, last_response['Location']
    assert_equal "Authorization dialog form", last_response.body
  end

  def test_redirect_when_permissions_granted
    uri = URI('/permissions')
    params = [
      ['client_id', 'testcid'],
      ['response_type', 'code'],
      ['scope' 'all']
    ]

    uri.query = URI.encode_www_form(params)

    post uri.to_s, {
      grant: 'yes'
    }

    code = Code::Store.last.code
    cb_uri = 'http://example.com/callback?code=' + code

    assert_equal 302, last_response.status
    assert_equal cb_uri, last_response.headers['Location']
  end

  def test_redirect_when_permissions_denied
    uri = URI('/permissions')
    params = [
      ['client_id', 'testcid'],
      ['response_type', 'code'],
      ['scope' 'all']
    ]

    uri.query = URI.encode_www_form(params)

    post uri.to_s, {
      grant: 'no'
    }

    cb_uri = 'http://example.com/callback?error=access_denied&error_description=Access+denied'

    assert_equal 302, last_response.status
    assert_equal cb_uri, last_response.headers['Location']
  end

  def test_redirect_when_permissions_granted_token_response_type
    uri = URI('/permissions')
    params = [
      ['client_id', 'testcid'],
      ['response_type', 'token'],
      ['scope' 'all']
    ]

    uri.query = URI.encode_www_form(params)

    post uri.to_s, {
      grant: 'yes'
    }

    assert_equal 302, last_response.status

    redirect_uri = URI(last_response.headers['Location'])
    parts = Hash[URI.decode_www_form(redirect_uri.fragment)]

    assert_equal 'Bearer', parts['token_type']
    assert parts.has_key?('access_token')
  end

  def test_respects_callback_uri_params
    uri = URI('/permissions')
    params = [
      ['client_id', 'testcid'],
      ['response_type', 'code'],
      ['scope' 'all'],
      ['redirect_uri', 'http://example.com/callback?extra=param']
    ]

    uri.query = URI.encode_www_form(params)

    post uri.to_s, {
      grant: 'yes'
    }

    code = Code::Store.last.code
    cb_uri = 'http://example.com/callback?extra=param&code=' + code

    assert_equal 302, last_response.status
    assert_equal cb_uri, last_response.headers['Location']
  end

  def test_respects_state_param
    uri = URI('/permissions')
    params = [
      ['client_id', 'testcid'],
      ['response_type', 'code'],
      ['scope' 'all'],
      ['state', 'state-value']
    ]

    uri.query = URI.encode_www_form(params)

    post uri.to_s, {
      grant: 'yes'
    }

    code = Code::Store.last.code
    cb_uri = 'http://example.com/callback?state=state-value&code=' + code

    assert_equal 302, last_response.status
    assert_equal cb_uri, last_response.headers['Location']
  end

  def test_implicit_grant
    uri = URI('/permissions')
    params = [
      ['client_id', 'testcid'],
      ['response_type', 'token'],
      ['scope' 'all']
    ]

    uri.query = URI.encode_www_form(params)

    post uri.to_s, {
      grant: 'yes'
    }

    assert_equal 302, last_response.status

    uri = URI(last_response.headers['Location'])
    fragment = uri.fragment
    uri.fragment = nil

    cb_uri = 'http://example.com/callback'

    assert_equal cb_uri, uri.to_s

    fragment_parts = Hash[URI.decode_www_form(fragment)]
    assert_equal ['access_token', 'token_type'], fragment_parts.keys.sort
    assert_equal 'Bearer', fragment_parts['token_type']

    unsigned = DummyDriver.token_signer.unsign(fragment_parts['access_token'])
    data = OAuth2Provider::Tokens::Bearer.unserialize(unsigned)

    # Owner.id, client.client_id, scope
    assert_equal ["1", "testcid", ["all"]], data.take(3)
  end

  def test_denied_implicit_grant
    uri = URI('/permissions')
    params = [
      ['client_id', 'testcid'],
      ['response_type', 'token'],
      ['scope' 'all']
    ]

    uri.query = URI.encode_www_form(params)

    post uri.to_s, {
      grant: 'no'
    }

    cb_uri = 'http://example.com/callback#error=access_denied&error_description=Access+denied'

    assert_equal 302, last_response.status
    assert_equal cb_uri, last_response.headers['Location']
  end

  def test_token_with_valid_owner_credentials
    authorize "testcid", "clientsecret"
    post "/oauth/access_token", {
      grant_type: 'password',
      username: 'user@example.com',
      password: 'password'
    }

    assert_equal 200, last_response.status
    assert_equal 'application/json', last_response.headers['Content-Type']

    token_json = {
      'token_type' => 'Bearer',
      'scope' => 'all',
      'expires_in' => DummyDriver.token_expires_in(nil)
    }
    result_json = JSON.parse(last_response.body)
    result_token = result_json.delete('access_token')

    assert_equal token_json, result_json

    unsigned = DummyDriver.token_signer.unsign(result_token)
    data = OAuth2Provider::Tokens::Bearer.unserialize(unsigned)

    # Owner.id, client.client_id, scope
    assert_equal ["1", "testcid", ["all"]], data.take(3)
  end

  def test_token_with_valid_owner_credentials_in_POST
    post "/oauth/access_token", {
      client_id: 'testcid',
      client_secret: 'clientsecret',
      grant_type: 'password',
      username: 'user@example.com',
      password: 'password'
    }

    assert_equal 200, last_response.status
    assert_equal 'application/json', last_response.headers['Content-Type']

    token_json = {
      'token_type' => 'Bearer',
      'scope' => 'all',
      'expires_in' => DummyDriver.token_expires_in(nil)
    }
    result_json = JSON.parse(last_response.body)
    result_token = result_json.delete('access_token')

    assert_equal token_json, result_json

    unsigned = DummyDriver.token_signer.unsign(result_token)
    data = OAuth2Provider::Tokens::Bearer.unserialize(unsigned)

    # Owner.id, client.client_id, scope
    assert_equal ["1", "testcid", ["all"]], data.take(3)
  end

  def test_token_with_invalid_owner_credentials
    authorize "testcid", "clientsecret"
    post "/oauth/access_token", {
      grant_type: 'password',
      username: 'invalid',
      password: 'invalid'
    }

    assert_equal 400, last_response.status
    assert_equal 'application/json', last_response.headers['Content-Type']

    token_json = {
      "error" => "access_denied",
      "error_description" => "Access denied"
    }
    assert_equal token_json, JSON.parse(last_response.body)
  end

  def test_with_invalid_client_credentials
    authorize "invalid", "invalid"
    post "/oauth/access_token", {
      grant_type: 'password',
      username: 'invalid',
      password: 'invalid'
    }

    assert_equal 401, last_response.status
    assert_equal 'application/json', last_response.headers['Content-Type']

    token_json = {
      "error" => "invalid_client",
      "error_description" => "Invalid client: client not found"
    }
    assert_equal token_json, JSON.parse(last_response.body)
    # As required by the spec, if we are using Basic auth ensure
    # we are included WWW-Authenticate in the response
    assert_equal 'Basic realm="Example.com"', last_response.headers['WWW-Authenticate']
  end

  def test_with_invalid_code
    authorize "testcid", "clientsecret"
    post "/oauth/access_token", {
      grant_type: 'authorization_code',
      redirect_uri: 'http://example.com/callback',
      code: 'invalid'
    }

    assert_equal 400, last_response.status
    assert_equal 'application/json', last_response.headers['Content-Type']

    token_json = {
      "error" => "invalid_grant",
      "error_description" => "Invalid grant: invalid code"
    }
    assert_equal token_json, JSON.parse(last_response.body)
  end

  def test_with_valid_code
    authorize "testcid", "clientsecret"
    post "/oauth/access_token", {
      grant_type: 'authorization_code',
      redirect_uri: @code.redirect_uri,
      code: @code.code
    }

    assert_equal 200, last_response.status
    assert_equal 'application/json', last_response.headers['Content-Type']

    token_json = {
      'token_type' => 'Bearer',
      'scope' => 'all',
      'expires_in' => DummyDriver.token_expires_in(nil)
    }
    result_json = JSON.parse(last_response.body)
    result_token = result_json.delete('access_token')
    refresh_token = result_json.delete('refresh_token')

    assert_equal token_json, result_json

    unsigned = DummyDriver.token_signer.unsign(result_token)
    data = OAuth2Provider::Tokens::Bearer.unserialize(unsigned)

    # Owner.id, client.client_id, scope
    assert_equal ["1", "testcid", ["all"]], data.take(3)
    assert refresh_token
  end

  def test_with_valid_code_bad_redirect_uri
    authorize "testcid", "clientsecret"
    post "/oauth/access_token", {
      grant_type: 'authorization_code',
      redirect_uri: 'http://invalid.com/cb',
      code: @code.code
    }

    assert_equal 400, last_response.status
    assert_equal 'application/json', last_response.headers['Content-Type']

    json = {
      'error'=>'invalid_grant',
      'error_description'=>"Invalid grant: 'redirect_uri' does not match"
    }

    assert_equal json, JSON.parse(last_response.body)
  end

  def test_with_valid_code_no_redirect_uri_needed
    authorize "testcid", "clientsecret"
    post "/oauth/access_token", {
      grant_type: 'authorization_code',
      code: @code_no_uri.code
    }

    assert_equal 200, last_response.status
    assert_equal 'application/json', last_response.headers['Content-Type']

    token_json = {
      'token_type' => 'Bearer',
      'scope' => 'all',
      'expires_in' => DummyDriver.token_expires_in(nil)
    }
    result_json = JSON.parse(last_response.body)
    result_token = result_json.delete('access_token')
    refresh_token = result_json.delete('refresh_token')

    assert_equal token_json, result_json

    unsigned = DummyDriver.token_signer.unsign(result_token)
    data = OAuth2Provider::Tokens::Bearer.unserialize(unsigned)

    # Owner.id, client.client_id, scope
    assert_equal ["1", "testcid", ["all"]], data.take(3)
    assert refresh_token
  end

  def test_client_credentials_with_valid_client
    authorize "testcid", "clientsecret"
    post "/oauth/access_token", {
      grant_type: 'client_credentials',
    }

    assert_equal 200, last_response.status
    assert_equal 'application/json', last_response.headers['Content-Type']

    token_json = {
      'token_type' => 'Bearer',
      'scope' => 'all',
      'expires_in' => DummyDriver.token_expires_in(nil)
    }

    result_json = JSON.parse(last_response.body)
    result_token = result_json.delete('access_token')

    assert result_token
    assert_equal token_json, result_json

    unsigned = DummyDriver.token_signer.unsign(result_token)
    data = OAuth2Provider::Tokens::Bearer.unserialize(unsigned)

    # Owner.id, client.client_id, scope
    assert_equal ["", "testcid", ["all"]], data.take(3)
  end

  def test_client_credentials_with_bad_redirect_uri
    authorize "testcid", "clientsecret"
    post "/oauth/access_token", {
      grant_type: 'client_credentials',
      redirect_uri: 'http://invalid.com/cb',
    }

    assert_equal 400, last_response.status
    assert_equal 'application/json', last_response.headers['Content-Type']

    json = {
      'error'=>'invalid_grant',
      'error_description'=>"Invalid grant: 'redirect_uri' does not match"
    }

    assert_equal json, JSON.parse(last_response.body)
  end

  def test_with_valid_refresh_token
    authorize "testcid", "clientsecret"

    refresh_token = Signer.sign 'MQl0ZXN0Y2lkCWFsbAkFUuGQCQAAAAA=' # timestamp

    post "/oauth/access_token", {
      grant_type: 'refresh_token',
      refresh_token: refresh_token
    }

    assert_equal 200, last_response.status
    assert_equal 'application/json', last_response.headers['Content-Type']

    token_json = {
      'token_type' => 'Bearer',
      'scope' => 'all',
      'expires_in' => DummyDriver.token_expires_in(nil)
    }
    result_json = JSON.parse(last_response.body)
    result_token = result_json.delete('access_token')

    assert_equal token_json, result_json

    unsigned = DummyDriver.token_signer.unsign(result_token)
    data = OAuth2Provider::Tokens::Bearer.unserialize(unsigned)

    # Owner.id, client.client_id, scope
    assert_equal ["1", "testcid", ["all"]], data.take(3)
  end

  def test_token_debug_endpoint
    token = OAuth2Provider::Tokens::Bearer.new(
      @client, @owner, ["all"], signer: DummyDriver.token_signer
    )
    header "Authorization", "Bearer " + token.access_token
    get "/oauth/access_token_debug"

    assert_equal 200, last_response.status
    assert_equal 'application/json', last_response.headers['Content-Type']

    result_json = JSON.parse(last_response.body)
    expected = {"owner_id"=>"1", "client_key"=>"testcid", "scope"=>["all"]}

    assert_equal expected, result_json
  end

  def test_token_debug_with_invalid_token
    header "Authorization", "Bearer invalid-token"
    get "/oauth/access_token_debug"

    assert_equal 200, last_response.status
    assert_equal 'application/json', last_response.headers['Content-Type']

    result_json = JSON.parse(last_response.body)
    expected = {"error" => [
      401, {"WWW-Authenticate"=>"Bearer realm=\"Example.com\", error=\"invalid_token\", error_description=\"Invalid token\""}, []
    ]}

    assert_equal expected, result_json
  end

  def test_authorization_endpoint_handler_uri_compare
    inst = OAuth2Provider::AuthorizationEndpointHandler.new DummyDriver

    assert inst.uri_compare('http://example/',               nil)
    assert inst.uri_compare(nil,                             'http://example/')
    assert inst.uri_compare('',                              'http://example/')
    assert inst.uri_compare('http://example/',               'http://example/')
    assert inst.uri_compare('http://example/',               'http://example/?a=b')
    assert inst.uri_compare('http://example/?a=b',           'http://example/?a=b')
    refute inst.uri_compare('http://example/?a=b',           'http://example/')
    assert inst.uri_compare('a http://foo/',                 'http://foo/')
    assert inst.uri_compare('a http://foo/?a=b',             'http://foo/?a=b')
    refute inst.uri_compare('a http://foo/?a=b',             'http://foo/?b=a')
    assert inst.uri_compare('a http://foo/?a=b http://foo/', 'http://foo/?b=a')
  end
end
