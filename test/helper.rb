require 'minitest/autorun'
require 'oauth2_provider'
require 'nobi'
require 'rack/test'

class Owner < Struct.new(:id, :email, :password)
  Store = []
  def self.find_by_id id
    Store.find {|u| u.id == id}
  end

  def self.authenticate email, pass
    Store.find {|u| u.email == email and u.password == pass }
  end

  def initialize *args
    super
    Store << self
  end
end

class Client < Struct.new(:client_id, :secret_key, :default_scope, :redirect_uri)
  Store = []
  def self.find_by_client_id id
    Store.find {|u| u.client_id == id}
  end

  def initialize *args
    super
    Store << self
  end
end

class Code < Struct.new(:code, :scope, :owner_id, :client_id, :redirect_uri)
  Store = []

  def self.find code
    # find should remove the code after first lookup.
    Store.
      find {|c| c.code == code}.
      tap  {|c| Store.delete c }
  end

  def initialize *args
    super
    Store << self
  end
end

Signer = OAuth2Provider::Driver::Signer.new('secret')

class DummyDriver
  extend OAuth2Provider::Driver

  def self.find_client id
    Client.find_by_client_id id
  end

  def self.find_owner id
    Owner.find_by_id id.to_i
  end

  def self.authenticate e, p, r
    Owner.authenticate e, p
  end

  def self.token_signer
    Signer
  end

  def self.realm
    'Example.com'
  end

  def self.code_data(code)
    if data = Code.find(code)
      [data.scope.split, data.client_id, data.owner_id, data.redirect_uri]
    end
  end

  def self.store_code(code, scope, client_id, owner_id, redirect_uri)
    Code.new(code, scope, client_id, owner_id, redirect_uri)
  end
end

module App
  def self.call(env)
    request = Rack::Request.new(env)

    if request.get?
      [200, {}, ["Authorization dialog form"]]
    elsif request.post?
      if request.POST['grant'] == 'yes'
        env['oauth2-provider.authorizer'].grant!(1)
      else
        env['oauth2-provider.authorizer'].deny!
      end
    end
  end
end

class TestOAuth2Provider < Minitest::Test
end
