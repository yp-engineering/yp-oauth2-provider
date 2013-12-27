module OAuth2Provider
  module Tokens
    class Base
      DEFAULT_EXPIRE_TIME = 60*60*24*90 # in seconds (90 days)
      EPOCH = 1293840000

      attr_reader :client, :owner, :scope, :refresh_token
      attr_accessor :expires_in, :created_at

      def self.unserialize(value)
        owner_id, client_key, scope, created_at, expires_in =
          value.unpack('m0').first.split("\t", -1)
        scope = scope.split
        created_at = Time.at(bytes_to_int(created_at) + EPOCH).utc
        expires_in = bytes_to_int(expires_in)

        [owner_id, client_key, scope, created_at, expires_in]
      end

      def self.int_to_bytes(n)
        bytes = [n >> 24 & 0xff, n >> 16 & 0xff, n >> 8 & 0xff, n & 0xff]
        bytes.map(&:chr).join
      end

      def self.bytes_to_int(bytes)
        bytes.each_byte.inject(0) do |acc, byte|
          acc << 8 | byte
        end
      end

      def self.serialize(owner_id, client_id, scope, created_at, expires_in)
        created_at_bytes = int_to_bytes(created_at.to_i - EPOCH)
        expires_in_bytes = int_to_bytes(expires_in)

        [
          [owner_id, client_id, scope.join(' '),
           created_at_bytes, expires_in_bytes].join("\t")
        ].pack('m0')
      end

      def initialize(client, owner, scope, options = {})
        @client, @owner, @scope = client, owner, scope
        @expires_in = @refresh_token = nil
        @created_at = Time.now.utc
        @options = options
      end

      def access_token
        @access_token ||= generate(@options)
      end

      def to_json
        data = {
          access_token: access_token,
          token_type: token_type,
          scope: (scope || client.default_scope).join(' ')
        }

        data[:expires_in] = @expires_in if @expires_in
        data[:refresh_token] = @refresh_token if @refresh_token

        data.to_json
      end

      alias_method :to_str, :to_json

      def serialize(expires_in: @expires_in || 0)
        tok = self.class.serialize(owner ? owner.id : nil, client.client_id, scope, created_at, expires_in)
        [tok, owner, client, scope, created_at, expires_in]
      end

      def add_refresh!(signer)
        # refresh tokens don't expire
        @refresh_token = signer.sign(*serialize(expires_in: 0))
      end

      def generate(options = {})
        raise NotImplementedError
      end

      def token_type
        raise NotImplementedError
      end
    end

    class Bearer < Base
      def generate(options = {})
        signer = options[:signer]
        signer.sign(*serialize)
      end

      def token_type
        'Bearer'
      end
    end
  end
end
