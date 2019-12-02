#!/bin/ruby
# frozen_string_literal: true

require 'openssl'
require 'jwt'
secret_key = OpenSSL::PKey.read(File.read('fixtures/sample.key'))
jwt_algo = 'RS256'

payload = {
  "iat": Time.now.to_i,
  "exp": Time.now.to_i + 36_000, # Expires in ten hours
  "sub": 'session',
  "iss": 'barong',
  # "aud": %w[peatio barong],
  "jti": '1111111111',
  "uid": 'IDABC0000001',
  "email": 'admin@barong.io',
  "role": 'admin',
  "level": 3,
  "state": 'active',
  "referral_id": nil
}

puts JWT.encode(payload, secret_key, jwt_algo)
