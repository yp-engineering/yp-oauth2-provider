require 'set'

module OAuth2Provider
  class AccessValidator
    attr_accessor :driver, :request, :scope

    def initialize(request, driver)
      @request, @driver = request, driver
    end

    def halt klass, *args
      line = caller.first
      driver.logger.fatal(klass){ line }
      throw CATCH_SYMBOL, klass.new(*args).to_a
    end

    def verify!(*required_scope)
      # Errors defined in http://tools.ietf.org/html/rfc6750#section-3.1
      realm = driver.realm

      if signature = request.authorization('Bearer')
        begin
          @owner_id, @client_key, @scope, created_at, expires_in =
            Tokens::Bearer.unserialize(driver.token_signer.unsign(signature))
        rescue driver.unsign_error
          halt InvalidTokenErrorResponse, realm: realm
        end

        # Check if not expired (if expires_in = 0, it means it doesn't expire)
        if expires_in > 0 && Time.now.utc > created_at + expires_in
          halt InvalidTokenErrorResponse, realm: realm
        end

        # Required scope should be included in provided scope
        # TODO: token scope should be validated with owner<->client
        # provided scope too
        if driver.validate_scope(required_scope, scope, @client_key, @owner_id)
          self
        else
          halt InsufficientScopeErrorResponse, required_scope, realm: realm
        end
      else
        halt AccessRequiredResponse, realm: realm
      end
    end

    def owner
      @owner ||= driver.find_owner @owner_id
    end

    def client
      @client ||= driver.find_client @client_key
    end

    def to_json
      {
        owner_id: @owner_id,
        client_key: @client_key,
        scope: @scope,
      }.to_json
    end

    # == Unauthorized access responses

    class AuthFailureResponse
      def initialize(realm: realm)
        @realm = realm
      end

      def to_a
        [code, headers, body]
      end

      def code
        401
      end

      def headers
        { 'WWW-Authenticate' => auth_failure_message }
      end

      def body
        []
      end

      def auth_failure_message
        "Bearer realm=\"#{@realm}\""
      end
    end

    class AccessRequiredResponse < AuthFailureResponse
    end

    class InvalidTokenErrorResponse < AuthFailureResponse
      def auth_failure_message
        super + ', error="invalid_token", error_description="Invalid token"'
      end
    end

    class InsufficientScopeErrorResponse < AuthFailureResponse
      def initialize(required_scope, **opts)
        super(opts)
        @required_scope = required_scope.join(' ')
      end

      def code
        403
      end

      def auth_failure_message
        super + ", error=\"insufficient_scope\", error_description=\"Insufficient scope\", scope=\"#{@required_scope}\""
      end
    end
  end
end
