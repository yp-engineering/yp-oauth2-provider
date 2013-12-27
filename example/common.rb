require 'isolate/now'
require './lib/oauth2_provider'
require 'uri'
require 'cgi'
require 'nobi'
require 'json'

Owner = Struct.new('Owner', :id, :email, :password)
Client = Struct.new('Client',
                    :client_id, :secret_key, :default_scope, :redirect_uri)
Movie = Struct.new('Movie', :id, :owner_id, :title, :duration) do
  def to_json(state=nil)
    {id: id, owner_id: owner_id, title: title, duration: duration}.to_json
  end
end

module Store
  Clients = {}
  Owners = {}
  OwnersByEmail = {}
  Codes = {}
  Movies = {}
end

Store::Clients['client1'] =
  Client.new('client1', 'secret1', %w[movies_read movies_write],
             'http://client1.loc/cb')
Store::Clients['client2'] =
  Client.new('client2', 'secret1', %w[movies_read],
             'http://client2.loc/cb')

Store::Owners[1] = Store::OwnersByEmail['owner1@email.com'] =
  Owner.new(1, 'owner1@email.com', 'dragon1')
Store::Owners[2] = Store::OwnersByEmail['owner2@email.com'] =
  Owner.new(2, 'owner2@email.com', 'dragon2')

Store::Movies[1] = Movie.new(1, 1, 'Hobo with a shotgun', 93)
Store::Movies[2] = Movie.new(2, 2, 'Groundhog day', 100)

# O2P
class Driver
  include OAuth2Provider::Driver

  attr_reader :clients, :owners, :codes

  def initialize
    @signer = Nobi::Signer.new('----secret----')
  end

  def token_signer
    @signer
  end

  def authenticate(email, password, request)
    user = Store::OwnersByEmail[email]

    if user.password == password
      return user
    end
  end

  def find_client(client_id)
    Store::Clients[client_id]
  end

  def find_owner(owner_id)
    Store::Owners[owner_id.to_i]
  end

  def realm
    'example.com'
  end

  def code_data(code)
    Store::Codes.delete(code)
  end

  def store_code(code, scope, client_id, owner_id, redirect_uri)
    Store::Codes[code] = [scope, client_id, owner_id, redirect_uri]
  end

  def authorization_dialog_response(client, scope, redirect_uri, state, request)
    uri = URI('/permissions')
    uri.query = URI.encode_www_form(request.GET.to_a)

    [302, {'Location' => uri.to_s}, []]
  end

  def logger
    require 'logger'
    @logger ||= Logger.new STDERR
  end
end

module Render
  extend self

  LOGIN_TEMPLATE = <<-EOT
%s

<form method=POST action="%s">
  Username: <input name=email type=text value="%s" />
  Password: <input name=password type=password />

  <button>Login</button>
</form>
EOT

  PERMISSIONS_TEMPLATE = <<-EOT
<p>%s is asking for the following permissions:<p>

%s

<p>Allow?</p>

<form method=POST action="%s">
  <input type=submit name=grant value=yes />
  <input type=submit name=grant value=no />
</form>
EOT

  def login(action: '/login', email: '', errors: nil)
    LOGIN_TEMPLATE % [
      errors,
      CGI.escape_html(action),
      CGI.escape_html(email)]
  end

  def permissions(action: '/permissions', client_name: nil,
                  permissions: nil)
    PERMISSIONS_TEMPLATE % [
      CGI.escape_html(client_name),
      permissions,
      CGI.escape_html(action)]
  end
end
