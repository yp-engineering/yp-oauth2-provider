SYNOPSIS:
---------

### Example apps

Example apps can be found under the `example/` directory.

### Driver:

To enable OAuth2 Provider in your application, the first step is to complete the implementation of the "driver".

The easiest way to do this is to declare a class (or module) and includes the `OAuth2Provider::Driver` module (which provides defaults for most of the methods that the driver needs).

The "driver" must respond to the following methods:

- `access_token_path` (default provided): must return an object (usually a regexp) that is going to be compared with the request path to see if this is an access token request.
- `authorize_path` (default provided): must return an object (usually a regexp) that is going to be compared with the request path to see if this is an authorize request.
- `authenticate(email, password, request)`: this will be called to authenticate an user when using the [Resource Owner Password Credentials Grant](http://tools.ietf.org/html/rfc6749#section-4.3) type. Otherwise this method is optional.
- `find_client(client_id)`: should return an instance of the client identified with `client_id`. It should respond to: `client_id`, `default_scope`, `redirect_uri` and `secret_key`
- `find_owner(owner_id)`: should return an instance of the resource owner (the user) identified by `owner_id`
- `code_data(code)`: should return the data associated with the authorization code `code`. It must be an array of `scope`, `client_id`, `owner_id` and `redirect_uri`. This is used when using the [Authorization Code Grant](http://tools.ietf.org/html/rfc6749#section-4.1) type, otherwise this method is optional.
- `store_code(code, scope, client_id, owner_id, redirect_uri)`: should store the data associated with `code` so that it can be retrieved later with `code_data(code)`. This is used when using the [Authorization Code Grant](http://tools.ietf.org/html/rfc6749#section-4.1) type, otherwise this method is optional.
- `validate_scope(required, provided, client_id, owner_id)` (default provided): validates that `provided` is a valid scope then `required` is the scope needed to access a resource. Should return true if valid, false otherwise. The default implementation returns true if every scope element in `required` is also in `provided`.
- `allowed_grant_types(client)` (default provided): returns the list of grant_types allowed for a client. By default all supported grant types are allowed.
- `token_expires_in(token)` (default provided): returns the lifetime of token. The default implementation returns `OAuth2Provider::Tokens::Base::DEFAULT_EXPIRE_TIME` which equals to 90 days.
- `authorization_dialog_response(client, scope, redirect_uri, state, request)`: should return the response to be sent back to the user as part of the authorization flow. Could be a rendered login form or a redirect to the endpoint that implements the login/permissions grant form.
- `authorization_invalid_client_response(request, error)`: should return the response to be sent back to the user when the client is invalid.
- `realm`: the realm to be used with clients when authenticating (e.g. "example.com").
- `token_signer` (default provided): should return a signer object which responds to `sign(data, owner_id, client_id, scope, created_at, expires_in)` and `unsign(signed_data)`. The default is to use nobi's signer.
- `refresh_token_signer` (default provided): like `token_signer` but for refresh tokens. The default is to use the same signer as `token_signer`.
- `unsign_error` (default provided): should return the class of the exception raised by the signer objects when they fail to unsign some data. The default is `Nobi::BadSignature`
- `logger` (default provided): the logger object to be used. The default is an instance of `Logger` from the stdlib.

### Middleware:

The next step is to enable the `OAuth2Provider::Main` middleware.

```ruby
use OAuth2Provider::Main, YourDriver
```


### Access Authorizer

The access authorizer will be used by the application's authorization flow to either grant or deny access requested by a client application.

It is stored in `env['oauth2-provider.authorizer']` by the middleware and it responds to:

- `grant!(owner_id)`: has to be called when access has been granted by the owner/user.
- `deny!`: has to be called when access has been denied by the owner/user.

The place to interact with this object is usually the `POST` handler of the permissions dialog form.

Example (sinatra):

```ruby
helpers do
  def oauth_authorizer
    @oauth_authorizer ||= env['oauth2-provider.authorizer']
  end
end

post '/dialog/oauth' do
  oa = oauth_authorizer

  if request.POST['grant'] == 'true'
    oa.grant!(current_user.id)
  else
    oa.deny!
  end
end
```

The call to `grant!` will respond with the response corresponding to the provided `response_type` parameter containing either the `code` or `authorization_token` value to be used by the client.

Calling `deny!` will respond with the response corresponding to the provided `response_type` parameter including the error information.

### Access Validator

It is stored in `env['oauth2-provider.validator']` by the middleware and it responds to:

- `verify!(*required_scope)`: verifies that the client making the request has enough permissions to access this resource.
- `owner`: returns the associated owner. Available after `verify!` has been called.
- `client`: returns the associated client. Available after `verify!` has been called.

This object is used to protect resources that need OAuth2 permissions.

Example (sinatra):

```ruby
helpers do
  def oauth_validator
    @oauth_validator ||= env['oauth2-provider.validator']
  end
end

get '/me.json' do
  oauth_validator.verify!('read_user_data')

  oauth_validator.owner.to_json
end
```

The call to `verify!` will check that the current token is valid with the required scope, if it isn't (or if the token is not valid) it will abort with an authorized response.
