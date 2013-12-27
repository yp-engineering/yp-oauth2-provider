require './example/common'
require 'uri'

module Helpers
  NOT_FOUND_RESPONSE = [404, {}, ['Not found']].freeze
  METHOD_NOT_ALLOWED_RESPONSE = [405, {}, []].freeze

  def redirect(location)
    halt Rack::Response.new.tap {|r| r.redirect(location)}
  end

  def halt(response)
    throw :halt, response.to_a
  end

  def not_found
    halt NOT_FOUND_RESPONSE
  end

  def method_not_allowed
    halt METHOD_NOT_ALLOWED_RESPONSE
  end

  def render(body)
    [200, {'Content-Type' => 'text/html'}, [body]]
  end
end

module App
  extend self
  extend Helpers

  ROOT_RESPONSE = [200, {'Content-Type' => 'text/html'},
    ['<form method=POST action="/logout"><button>Logout']].freeze
  CSRF_PROTECTION_RESPONSE = [403, {}, []].freeze

  def call(env)
    request = Rack::Request.new(env)

    catch(:halt) do
      if request.path.start_with?('/api')
        ApiHandler.call(env)
      elsif request.post?
        handle_POST(request)
      elsif request.get?
        handle_GET(request)
      else
        method_not_allowed
      end
    end
  end

  def requires_login(request)
    if request.session['owner_id'].nil?
      redirect_uri = URI('/login')
      redirect_uri.query = URI.encode_www_form([['next', request.fullpath]])

      halt Rack::Response.new.tap{|r| r.redirect(redirect_uri.to_s)}
    end
  end

  def handle_GET(request)
    case request.path
    when '/'            then ROOT_RESPONSE
    when '/login'       then login_GET(request)
    when '/permissions' then permissions_GET(request)
    else                     not_found
    end
  end

  def handle_POST(request)
    referer = URI(request.referer)

    if referer.host != 'localhost'
      halt CSRF_PROTECTION_RESPONSE
    end

    case request.path
    when '/login'       then login_POST(request)
    when '/logout'      then logout_POST(request)
    when '/permissions' then permissions_POST(request)
    else                     not_found
    end
  end

  def login_GET(request)
    render(Render.login action: request.fullpath)
  end

  def login_POST(request)
    email, password = request.POST.values_at('email', 'password')

    if user = Store::OwnersByEmail[email] and user.password == password
      request.session['owner_id'] = user.id
      redirect request.GET.fetch('next', '/')
    else
      error = "<p>Login failed, try again</p>"

      render(Render.login(action: request.fullpath,
                          email: email, errors: error))
    end
  end

  def permissions_GET(request)
    requires_login(request)

    client = Store::Clients[request.GET['client_id']]

    if scope = request.GET['scope']
      scope = scope.split
    else
      scope = client.default_scope
    end

    permissions = scope.join(', ')

    render(Render.permissions(action: request.fullpath,
                              client_name: client.client_id,
                              permissions: permissions))
  end

  def permissions_POST(request)
    requires_login(request)

    authorizer = request.env['oauth2-provider.authorizer'] # O2P

    owner_id = request.session['owner_id']

    if request.POST['grant'] == 'yes'
      authorizer.grant!(owner_id) # O2P
    else
      authorizer.deny! # O2P
    end
  end

  def logout_POST(request)
    request.session.clear

    redirect '/'
  end
end

module ApiHandler
  extend self
  extend Helpers

  def json(value, status=200)
    Rack::Response.new([value.to_json], status,
                       {'Content-Type' => 'application/json'})
  end

  def call(env)
    request = Rack::Request.new(env)

    catch(:halt) do
      case request.path
      when %r{\A/api/movies/?\z}     then handle_movies_list(request)
      when %r{\A/api/movies/(\d+)\z} then handle_movie(request, Integer($1))
      end
    end
  end

  def handle_movies_list(request)
    validator = request.env['oauth2-provider.validator'] # O2P

    if request.get?
      validator.verify!('movies_read') # O2P

      movies = Store::Movies.values.select do |m|
        m.owner_id.to_s == validator.owner.id.to_s
      end

      json(movies)
    elsif request.post?
      validator.verify!('movies_write') # O2P
      title, duration = request.POST.values_at('title', 'duration')

      if title && duration
        id = Store::Movies.keys.max + 1
        Store::Movies[id] =
          Movie.new(id, validator.owner.id,
                    request.POST['title'],
                    request.POST['duration'].to_i)

        json({'success' => true, 'movie' => Store::Movies[id]}, 201)
      else
        json({'success' => false, 'error' => 'missing title and/or duration'},
             400)
      end
    else
      method_not_allowed
    end
  end

  def handle_movie(request, id)
    validator = request.env['oauth2-provider.validator'] # O2P
    id = Integer(id)

    if request.get?
      validator.verify!('movies_read') # O2P

      if movie = Store::Movies[id]
        if movie.owner_id == validator.owner.id
          json(movie)
        else
          json({'error' => 'movie not owned by this user'}, 403)
        end
      else
        not_found
      end
    elsif request.put?
      validator.verify!('movies_write') # O2P
      title, duration = request.POST.values_at('title', 'duration')
      movie = Store::Movies[id]

      if !movie
        not_found
      elsif movie.owner_id == validator.owner.id
        if title && duration
          movie.title = title
          movie.duration = duration

          json({'success' => true, 'movie' => movie}, 201)
        else
          json({'success' => false, 'error' => 'missing title and/or duration'},
               400)
        end
      else
        json({'error' => 'movie not owned by this user'}, 403)
      end
    else
      method_not_allowed
    end
  end
end


use OAuth2Provider::Main, Driver.new # O2P
use Rack::Session::Cookie, secret: '---session-secret---'

run App
