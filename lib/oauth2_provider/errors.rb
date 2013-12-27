module OAuth2Provider

  # ==== OAuth2 Errors
  #
  # As defined in:
  #
  #   http://tools.ietf.org/html/rfc6749#section-4.1.2.1
  #   http://tools.ietf.org/html/rfc6749#section-5.2

  class OAuth2Error < ::StandardError
    def initialize(message = nil)
      super([self.class.const_get('MESSAGE'), message].compact.join(': '))
    end

    def error
      self
    end

    def code
      self.class.const_get('CODE')
    end

    def response_error_code
      400
    end

    def response_headers(request)
      {
        'Content-Type' => 'application/json',
        'Content-Length' => Rack::Utils.bytesize(to_json).to_s
      }
    end

    def to_json
      {
        error: code,
        error_description: message
      }.to_json
    end

    def query_params
      [['error', code], ['error_description', message]]
    end
  end

  class AccessDeniedError < OAuth2Error
    CODE = 'access_denied'
    MESSAGE = 'Access denied'
  end

  class InvalidClientError < OAuth2Error
    CODE = 'invalid_client'
    MESSAGE = 'Invalid client'

    def initialize(msg = nil, realm: nil)
      @realm = realm
      super(msg)
    end

    def response_error_code
      401
    end

    def response_headers(request)
      super.tap do |h|
        if request.basic_auth?
          h['WWW-Authenticate'] = "Basic realm=\"#{@realm}\""
        end
      end
    end
  end

  class InvalidGrantError < OAuth2Error
    CODE = 'invalid_grant'
    MESSAGE = 'Invalid grant'
  end

  class InvalidRequestError < OAuth2Error
    CODE = 'invalid_request'
    MESSAGE = 'Invalid request'
  end

  class InvalidScopeError < OAuth2Error
    CODE = 'invalid_scope'
    MESSAGE = 'Invalid scope'
  end

  class ServerErrorError < OAuth2Error
    CODE = 'server_error'
    MESSAGE = 'Server error'
  end

  class TemporarilyUnavailableError < OAuth2Error
    CODE = 'temporarily_unavailable'
    MESSAGE = 'Temporarily unavailable'
  end

  class UnauthorizedClientError < OAuth2Error
    CODE = 'unauthorized_client'
    MESSAGE = 'Unauthorized client'
  end

  class UnsupportedGrantTypeError < OAuth2Error
    CODE = 'unsupported_grant_type'
    MESSAGE = 'Unsupported grant type'
  end

  class UnsupportedResponseTypeError < OAuth2Error
    CODE = 'unsupported_response_type'
    MESSAGE = 'Unsupported response type'
  end
end
