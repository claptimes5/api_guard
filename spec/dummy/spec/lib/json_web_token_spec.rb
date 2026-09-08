# frozen_string_literal: true

require 'dummy/spec/rails_helper'

# Regression guards for audit findings A2 (explicit algorithm allowlist) and
# A1 (the refresh path must relax expiry only, never signature verification).
describe ApiGuard::JwtAuth::JsonWebToken do
  include ApiGuard::JwtAuth::JsonWebToken

  let(:other_secret) { 'a-completely-different-secret' }
  let(:payload) { { user_id: 1, exp: 1.hour.from_now.to_i, iat: Time.now.to_i } }
  let(:expired_payload) { { user_id: 1, exp: 1.hour.ago.to_i, iat: 2.hours.ago.to_i } }

  describe 'signature and algorithm verification (A2)' do
    it 'decodes a token signed with HS256' do
      token = JWT.encode(payload, ApiGuard.token_signing_secret, 'HS256')

      expect(decode(token)[:user_id]).to eq(1)
    end

    %w[HS384 HS512].each do |algorithm|
      it "rejects a token signed with #{algorithm} using the correct secret" do
        token = JWT.encode(payload, ApiGuard.token_signing_secret, algorithm)

        expect { decode(token) }.to raise_error(JWT::IncorrectAlgorithm)
      end
    end

    it "rejects an unsigned 'alg: none' token" do
      token = JWT.encode(payload, nil, 'none')

      expect { decode(token) }.to raise_error(JWT::DecodeError)
    end

    it 'rejects a token signed with a different secret' do
      token = JWT.encode(payload, other_secret, 'HS256')

      expect { decode(token) }.to raise_error(JWT::VerificationError)
    end

    it 'rejects an expired token' do
      token = JWT.encode(expired_payload, ApiGuard.token_signing_secret, 'HS256')

      expect { decode(token) }.to raise_error(JWT::ExpiredSignature)
    end
  end

  describe 'with expiry verification relaxed, as on the refresh path (A1)' do
    it 'accepts an expired but authentically signed token' do
      token = JWT.encode(expired_payload, ApiGuard.token_signing_secret, 'HS256')

      expect(decode(token, false)[:user_id]).to eq(1)
    end

    it 'still rejects a token signed with a different secret' do
      token = JWT.encode(payload, other_secret, 'HS256')

      expect { decode(token, false) }.to raise_error(JWT::VerificationError)
    end

    it 'still rejects a token signed with HS512' do
      token = JWT.encode(payload, ApiGuard.token_signing_secret, 'HS512')

      expect { decode(token, false) }.to raise_error(JWT::IncorrectAlgorithm)
    end

    it "still rejects an unsigned 'alg: none' token" do
      token = JWT.encode(payload, nil, 'none')

      expect { decode(token, false) }.to raise_error(JWT::DecodeError)
    end
  end
end
