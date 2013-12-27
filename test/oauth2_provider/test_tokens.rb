require 'helper'

class TestOAuth2Provider::TestTokens < Minitest::Test
  def test_unserialize_with_empty_scope
    klass = OAuth2Provider::Tokens::Bearer
    c = 'c1'; def c.client_id() self end
    o = 'o1'; def o.id() self end
    tok = klass.new c, o, [], signer: Signer

    expected = ['o1', 'c1', []]
    assert_equal expected, klass.unserialize(tok.serialize.first).take(3)
  end

  def test_add_refresh_bang_passes_other_options
    refresh_signer = Class.new do
      attr_reader :args
      def sign(*args) @args = args; args.first end
    end.new
    klass = OAuth2Provider::Tokens::Bearer
    c = 'c1'; def c.client_id() self end
    o = 'o1'; def o.id() self end
    tok = klass.new c, o, []
    tok.add_refresh!(refresh_signer)

    expected = [o, c, []]
    assert_equal expected, refresh_signer.args[1,3]
  end
end
