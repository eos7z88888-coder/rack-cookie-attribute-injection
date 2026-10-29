# Regression test for the Rack::Utils.set_cookie_header attribute validation.
# Drop into rack's own suite as test/spec_cookie_attributes.rb and run:
#   ruby -Ilib -Itest test/spec_cookie_attributes.rb
require_relative "helper"
require "rack/utils"

describe Rack::Utils, "set_cookie_header attribute validation" do
  it "rejects CRLF in :domain" do
    assert_raises(ArgumentError) do
      Rack::Utils.set_cookie_header("sid", { value: "v", domain: ".evil.example\r\nadmin=1" })
    end
  end

  it "rejects CRLF in :path" do
    assert_raises(ArgumentError) do
      Rack::Utils.set_cookie_header("sid", { value: "v", path: "/\r\nX-Injected: 1" })
    end
  end

  it "rejects CRLF in :max_age" do
    assert_raises(ArgumentError) do
      Rack::Utils.set_cookie_header("sid", { value: "v", max_age: "10\r\nX-Injected: 1" })
    end
  end

  it "rejects a bare response-splitting payload in :path" do
    assert_raises(ArgumentError) do
      Rack::Utils.set_cookie_header("sid", { value: "v", path: "/\r\n\r\nHTTP/1.1 200 OK" })
    end
  end

  it "still accepts legitimate attribute values" do
    header = Rack::Utils.set_cookie_header("sid",
      { value: "v", domain: ".example.com", path: "/app/section", max_age: 3600 })
    header.must_include "domain=.example.com"
    header.must_include "path=/app/section"
    header.must_include "max-age=3600"
  end

  it "still accepts an IPv4 / localhost domain and the root path" do
    header = Rack::Utils.set_cookie_header("sid", { value: "v", domain: "127.0.0.1", path: "/" })
    header.must_include "domain=127.0.0.1"
    header.must_include "path=/"
  end
end
