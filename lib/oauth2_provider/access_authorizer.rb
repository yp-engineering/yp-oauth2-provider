require 'securerandom'

module OAuth2Provider
  class AccessAuthorizer
    AUTHORIZER_GRANT_RESPONSE_TYPES = {}
    AUTHORIZER_DENY_RESPONSE_TYPES = {}

    attr_reader :driver, :scope, :client, :client_id, :owner_id, :state
    attr_reader :response_type, :redirect_uri

    def initialize(request, driver)
      @driver = driver
      @state = request.GET['state']
      @client_id = request.GET['client_id']
      @response_type = request.GET['response_type']
      @client = driver.find_client(@client_id)
      @scope = request.GET['scope'] && request.GET['scope'].split
      @scope ||= @client.default_scope

      # Store the provided redirect_uri without using the one registered
      # by client so that we can differentiate when one was provided
      # vs none was and only validate when needed
      @redirect_uri = request.GET['redirect_uri']
    end

    def actual_redirect_uri
      redirect_uri || @client.redirect_uri
    end

    def owner
      @owner ||= driver.find_owner(owner_id)
    end

    def halt(response)
      throw CATCH_SYMBOL, response.to_a
    end

    def invalid_request
      error = InvalidRequestError.new

      driver.logger.fatal error

      response = Response.new(error, error.response_error_code,
                              error.response_headers(nil))

      halt response
    end

    def grant!(owner_id)
      @owner_id = owner_id

      klass = AUTHORIZER_GRANT_RESPONSE_TYPES.fetch(response_type)

      halt klass.new(self)
    rescue KeyError
      invalid_request
    end

    def deny!
      klass = AUTHORIZER_DENY_RESPONSE_TYPES.fetch(response_type)

      halt klass.new(self)
    rescue KeyError
      invalid_request
    end

    # == Grant/Deny responses

    module URIHelper
      def self.append_get_params(uri_str, params)
        URI(uri_str).tap do |uri|
          query_params = URI.decode_www_form(uri.query || '')
          query_params.concat(params)

          uri.query = URI.encode_www_form(query_params)
        end.to_s
      end

      def self.append_fragment_params(uri_str, params)
        URI(uri_str).tap do |uri|
          uri.fragment = URI.encode_www_form(params)
        end.to_s
      end
    end

    class AuthorizerResponse
      attr_reader :authorizer

      def initialize(authorizer)
        @authorizer = authorizer
      end

      def redirect_uri_params_mode
        :query
      end

      def redirect_uri
        @redirect_uri ||=
          case redirect_uri_params_mode
          when :query then
            URIHelper.append_get_params(authorizer.actual_redirect_uri,
                                        response_params)
          when :fragment then
            URIHelper.append_fragment_params(authorizer.actual_redirect_uri,
                                             response_params)
          end
      end

      def response_params
        [].tap do |result|
          result << ['state', authorizer.state] if authorizer.state
        end
      end

      def driver
        authorizer.driver
      end

      def to_a
        [code, headers, body]
      end

      def body
        ['Redirecting...']
      end

      def code
        302
      end

      def headers
        len = body.inject(0){|l, p| l + Rack::Utils.bytesize(p)}

        {
          'Content-Length' => len.to_s,
          'Location' => redirect_uri
        }
      end
    end

    class AuthorizerCodeGrantResponse < AuthorizerResponse
      # http://tools.ietf.org/html/rfc6749#section-4.1

      AUTHORIZER_GRANT_RESPONSE_TYPES['code'] = self

      def generate_code
        SecureRandom.urlsafe_base64(16)
      end

      def response_params
        code = generate_code

        scope, redirect_uri = authorizer.scope, authorizer.redirect_uri
        client_id, owner_id = authorizer.client_id, authorizer.owner_id

        driver.store_code(code, scope, client_id, owner_id, redirect_uri)

        super.tap do |result|
          result << ['code', code]
        end
      end
    end

    class AuthorizerImplicitGrantResponse < AuthorizerResponse
      # http://tools.ietf.org/html/rfc6749#section-4.2

      AUTHORIZER_GRANT_RESPONSE_TYPES['token'] = self

      def generate_token
        Tokens::Bearer.new(authorizer.client,
                           authorizer.owner,
                           authorizer.scope,
                           signer: driver.token_signer)
      end

      def redirect_uri_params_mode
        :fragment
      end

      def response_params
        token = generate_token

        super.tap do |result|
          result << ['access_token', token.access_token]
          result << ['token_type', token.token_type]
        end
      end
    end

    class AuthorizerDenyCodeResponse < AuthorizerResponse
      AUTHORIZER_DENY_RESPONSE_TYPES['code'] = self

      def response_params
        [
          ['error', 'access_denied'],
          ['error_description', 'Access denied']
        ]
      end
    end

    class AuthorizerDenyImplicitResponse < AuthorizerDenyCodeResponse
      AUTHORIZER_DENY_RESPONSE_TYPES['token'] = self

      def redirect_uri_params_mode
        :fragment
      end
    end
  end
end
