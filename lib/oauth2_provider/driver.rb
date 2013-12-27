module OAuth2Provider
  module Driver
    begin
      require 'nobi'
      class Signer < Nobi::TimestampSigner
        def sign(tok, *)
          super tok
        end
      end
      @@signer    = Signer.new(SecureRandom.random_bytes(32))
      UnsignError = Nobi::BadSignature
    rescue LoadError
      # no default signer
    end

    def access_token_path
      %r{\A/oauth/access_token/?\z}
    end

    def access_token_debug_path
      %r{\A/oauth/access_token_debug/?\z}
    end

    ##
    # must return owner

    def authenticate(email, password, request)
      raise NotImplementedError
    end

    def authorize_path
      %r{\A/oauth/authorize/?\z}
    end

    ##
    # client must respond to:
    #
    #   client_id
    #   default_scope
    #   redirect_uri
    #   secret_key

    def find_client(client_id)
      raise NotImplementedError
    end

    ##
    # owner must respond to:
    #
    #   id

    def find_owner(owner_id)
      raise NotImplementedError
    end

    ##
    # Retrieves data associated with code, must return nil if code
    # doesn't exist, otherwise an array of:
    #
    #   scope
    #   client_id
    #   owner_id
    #   redirect_uri

    def code_data(code)
      raise NotImplementedError
    end

    def store_code(code, scope, client_id, owner_id, redirect_uri)
      raise NotImplementedError
    end

    def validate_scope(required, provided, client_id, owner_id)
      Set.new(required) <= Set.new(provided)
    end

    def allowed_grant_types(client)
      GRANT_TYPE_HANDLERS.keys
    end

    def token_expires_in(token)
      Tokens::Base::DEFAULT_EXPIRE_TIME
    end

    def authorization_dialog_response(client, scope, redirect_uri, state, request)
      [200, {}, ["Authorization dialog form"]]
    end

    def authorization_invalid_client_response(request, error)
      [400, {}, ["Invalid client"]]
    end

    def realm
      raise NotImplementedError
    end

    def token_signer
      raise NotImplementedError unless defined?(@@signer)
      @@signer
    end

    def refresh_token_signer
      token_signer
    end

    ##
    # The error class raised by unsign for an invalid signature.

    def unsign_error
      raise NotImplementedError unless defined?(UnsignError)
      UnsignError
    end

    def logger
      @logger ||= begin
                    require 'logger'
                    Logger.new nil
                  end
    end
    attr_writer :logger

  end
end
