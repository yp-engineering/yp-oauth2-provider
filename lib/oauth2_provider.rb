require 'rack'
require 'json'

require_relative 'oauth2_provider/access_validator'
require_relative 'oauth2_provider/access_authorizer'
require_relative 'oauth2_provider/driver'
require_relative 'oauth2_provider/errors'
require_relative 'oauth2_provider/tokens'

module OAuth2Provider
  VERSION = '0.5.3'
  CATCH_SYMBOL = :oauth2_provider_halt

  # ==== OAuth2 extended Request and Response

  class Request < ::Rack::Request
    attr_accessor :driver

    def grant_type
      self.POST['grant_type']
    end

    def realm
      driver.realm
    end

    # == Client Authentication
    # http://tools.ietf.org/html/rfc6749#section-2.3

    def basic_auth?
      authorization 'Basic'
    end

    def authorization(type)
      env['HTTP_AUTHORIZATION'] =~ /#{type} (.+)/ and $1
    end

    def credentials
      if value = basic_auth?
        client, secret = value.unpack('m*')[0].split(':')
      else
        ps = self.post? ? self.POST : self.GET
        client, secret = ps.values_at('client_id', 'client_secret')
      end

      [client, secret]
    end

    def client
      @client ||=
        begin
          client_id, client_secret = self.credentials

          if client_id.nil?
            raise InvalidClientError.new('missing client_id', realm: realm)
          end

          unless client = driver.find_client(client_id)
            raise InvalidClientError.new('client not found', realm: realm)
          end

          if self.post? && client.secret_key != client_secret
            raise InvalidClientError.new('failed to authenticate client',
                                         realm: realm)
          end

          client
        end
    end

    def scope
      scope_string = self.post? ? self.POST['scope'] : self.GET['scope']

      if scope_string
        scope_string.split
      else
        client.default_scope
      end
    end
  end

  class Response < ::Rack::Response
    # Headers that MUST be included as specified by rfc6749
    DEFAULT_HEADERS = {
      'Content-Type' => 'application/json',
      'Cache-Control' => 'no-store',
      'Pragma' => 'no-cache'
    }

    def initialize(body=[], status=200, header={})
      super(body, status, DEFAULT_HEADERS.merge(header))
    end
  end

  class RedirectResponse < ::Rack::Response
    def initialize(redirect_uri, params)
      super()
      uri = URI(redirect_uri)
      query_params = URI.decode_www_form(uri.query || '')
      query_params.concat(params.to_a)
      uri.query = URI.encode_www_form(query_params)

      write('Redirecting...')

      redirect uri.to_s
    end
  end

  # ====  Entry point

  class Main
    attr_reader :driver

    def initialize(app, driver)
      @driver = driver
      @app = app

      @token_endpoint_handler = TokenEndpointHandler.new(driver)
      @token_debug_endpoint_handler = TokenDebugEndpointHandler.new(driver)
      @authorization_endpoint_handler = AuthorizationEndpointHandler.new(driver)
    end

    def call(env)
      request = Request.new(env)
      request.driver = driver

      case request.path
      when driver.access_token_debug_path then
        @token_debug_endpoint_handler.call(request)
      when driver.access_token_path then
        @token_endpoint_handler.call(request)
      when driver.authorize_path then
        @authorization_endpoint_handler.call(request)
      else
        # TODO: request haves a reference to driver, maybe we can
        # just avoid passing driver here?
        env['oauth2-provider.validator'] =
          AccessValidator.new(request, driver)

        if request.GET['client_id']
          env['oauth2-provider.authorizer'] =
            AccessAuthorizer.new(request, driver)
        end

        catch(CATCH_SYMBOL) { @app.call(env) }
      end
    end
  end

  class TokenDebugEndpointHandler
    RESP = [200, {'Content-Type' => 'application/json'}].freeze

    def initialize(driver)
      @driver = driver
    end

    def call(request)
      validator = AccessValidator.new(request, @driver)
      error = catch(CATCH_SYMBOL) do
        validator.verify!
        return RESP + [[validator.to_json]]
      end
      # invalid signature
      RESP + [[{error: error}.to_json]]
    end
  end

  # ==== Endpoint Handlers

  class TokenEndpointHandler
    # == Token Endpoint
    # http://tools.ietf.org/html/rfc6749#section-3.2

    attr_reader :driver, :grant_type_handlers

    def initialize(driver)
      @driver = driver
      @grant_type_handlers = {}

      GRANT_TYPE_HANDLERS.each do |k, grant_handler_class|
        @grant_type_handlers[k] = grant_handler_class.new(driver)
      end
    end

    def call(request)
      _call(request)
    rescue OAuth2Error => error
      driver.logger.fatal error

      response = Response.new(error.to_json, error.response_error_code,
                              error.response_headers(request))

      response.finish
    end

    def _call(request)
      grant_type = request.grant_type or
        raise InvalidRequestError.new('missing grant_type')

      allowed_grant_types = driver.allowed_grant_types(request.client)

      unless allowed_grant_types.include?(grant_type)
        raise UnsupportedGrantTypeError.new("unknown grant type: '#{grant_type}'")
      end

      handler = grant_type_handlers.fetch(grant_type)
      handler.call(request)
    rescue KeyError
      # GRANT_TYPE_HANDLER indexing failure
      raise UnsupportedGrantTypeError.new("unknown grant type: '#{grant_type}'")
    end
  end

  class AuthorizationEndpointHandler
    # == Authorization Endpoint
    # http://tools.ietf.org/html/rfc6749#section-3.1

    attr_reader :driver

    def initialize(driver)
      @driver = driver
    end

    def call(request)
      _call(request)
    rescue InvalidClientError => error
      driver.logger.fatal error

      driver.authorization_invalid_client_response(request, error)
    rescue OAuth2Error => error
      driver.logger.fatal error

      response = RedirectResponse.new(request.client.redirect_uri,
                                      error.query_params)

      response.finish
    end

    def _call(request)
      client = request.client
      scope = request.scope
      state = request.GET['state']
      response_type = request.GET.fetch('response_type')
      redirect_uri = request.GET['redirect_uri']

      unless uri_compare(client.redirect_uri, redirect_uri)
        raise InvalidRequestError.new("'redirect_uri' doesn't match")
      end

      unless %w[code token].include? response_type
        raise UnsupportedGrantTypeError.new("invalid response type '#{response_type}'")
      end

      driver.authorization_dialog_response(client, scope, redirect_uri,
                                           state, request)
    rescue KeyError
      # Missing response type
      raise InvalidRequestError.new("missing 'response_type' param")
    end

    # http://tools.ietf.org/html/rfc6749#section-3.1.2
    def uri_compare(client_redirect_uri, redirect_uri)
      return true unless redirect_uri
      return true if client_redirect_uri.nil? or client_redirect_uri.empty?

      redirect_uri_without_query = redirect_uri.split(/\?/)[0]
      client_redirect_uri.split.any? do |client_uri|
        client_uri == redirect_uri or client_uri == redirect_uri_without_query
      end
    end

  end

  # ==== Grant type handlers

  # Handlers will add themselves here
  GRANT_TYPE_HANDLERS = {} # grant_type => Handler

  class GrantTypePasswordHandler
    # == Resource Owner Password Credentials Grant
    # http://tools.ietf.org/html/rfc6749#section-4.3

    GRANT_TYPE_HANDLERS['password'] = self

    attr_reader :driver

    def initialize(driver)
      @driver = driver
    end

    def call(request)
      client = request.client

      username = request.POST.fetch('username')
      password = request.POST.fetch('password')
      scope = request.scope

      owner = driver.authenticate(username, password, request) or raise AccessDeniedError
      token = Tokens::Bearer.new(client, owner, scope,
                                 signer: driver.token_signer)
      token.expires_in = driver.token_expires_in(token)

      response = Response.new(token, 200)

      response.finish
    rescue KeyError
      # Missing username or password
      raise InvalidRequestError.new("missing 'username' or 'password' param")
    end
  end

  class GrantTypeAuthorizationCodeHandler
    # == Authorization Code Grant
    # http://tools.ietf.org/html/rfc6749#section-4.1

    GRANT_TYPE_HANDLERS['authorization_code'] = self

    attr_reader :driver

    def initialize(driver)
      @driver = driver
    end

    def call(request)
      client = request.client
      code = request.POST.fetch('code')

      code_data = driver.code_data(code) or
        raise InvalidGrantError.new('invalid code')

      scope, client_id, owner_id, code_redirect_uri = code_data

      redirect_uri = request.POST['redirect_uri']

      if code_redirect_uri && code_redirect_uri != redirect_uri
        raise InvalidGrantError.new("'redirect_uri' does not match")
      end

      if client_id != client.client_id
        raise InvalidGrantError.new("'client_id' does not match")
      end

      owner = driver.find_owner(owner_id) or
        raise InvalidGrantError.new("owner with 'owner_id' not found")

      token = Tokens::Bearer.new(client, owner, scope,
                                 signer: driver.token_signer)
      token.expires_in = driver.token_expires_in(token)

      # This code grant is the only one with refresh tokens
      # if the token will not expire, then we don't issue a refresh_token
      if token.expires_in
        token.add_refresh!(driver.refresh_token_signer)
      end

      response = Response.new(token, 200)

      response.finish
    rescue KeyError
      # Missing code or redirect_uri parameters
      raise InvalidRequestError.new("missing 'code' or 'redirect_uri' param")
    end
  end

  class GrantTypeRefreshTokenHandler
    # == Refresh token
    # http://tools.ietf.org/html/rfc6749#section-6

    GRANT_TYPE_HANDLERS['refresh_token'] = self

    attr_reader :driver

    def initialize(driver)
      @driver = driver
    end

    def call(request)
      client = request.client
      refresh_token = request.POST.fetch('refresh_token')
      unsigned_refresh_token = driver.refresh_token_signer.unsign(refresh_token)

      refresh_data = Tokens::Base.unserialize(unsigned_refresh_token)

      owner_id, client_id, scope = refresh_data

      if client_id != client.client_id
        raise InvalidGrantError.new("'client_id' does not match")
      end

      owner = driver.find_owner(owner_id) or
        raise InvalidGrantError.new("owner with 'owner_id' not found")

      token = Tokens::Bearer.new(client, owner, scope,
                                 signer: driver.token_signer)
      token.expires_in = driver.token_expires_in(token)

      response = Response.new(token, 200)

      response.finish
    rescue KeyError
      # Missing refresh_token parameter
      raise InvalidRequestError.new("missing 'refresh_token' param")
    rescue driver.unsign_error
      # Invalid token
      raise InvalidGrantError.new("token is invalid")
    end
  end

  class GrantTypeClientCredentialsHandler
    # == Client Credentials
    # http://tools.ietf.org/html/rfc6749#section-4.4

    GRANT_TYPE_HANDLERS['client_credentials'] = self

    attr_reader :driver

    def initialize(driver)
      @driver = driver
    end

    def call(request)
      client = request.client
      scope = request.scope

      # Check redirect URI
      redirect_uri = request.POST['redirect_uri']
      if redirect_uri && client.redirect_uri && client.redirect_uri != redirect_uri
        raise InvalidGrantError.new("'redirect_uri' does not match")
      end

      # Create token
      token = Tokens::Bearer.new(client, nil, scope,
                                 signer: driver.token_signer)
      token.expires_in = driver.token_expires_in(token)

      # Return response
      response = Response.new(token, 200)
      response.finish

    rescue driver.unsign_error
      # Invalid token
      raise InvalidGrantError.new("token is invalid")
    end
  end
end
