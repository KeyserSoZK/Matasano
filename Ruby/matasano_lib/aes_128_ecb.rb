require 'openssl'
require_relative 'aes_128_common'
require_relative 'pkcs7'

module MatasanoLib
  module AES_128_ECB
    class << self
      # padded: false skips PKCS#7 — CBC/CTR use ECB as a raw block cipher on block-aligned input.
      def encrypt(plaintext, key, opts = {})
        opts[:padded] = true if opts[:padded].nil?
        cipher = OpenSSL::Cipher.new('AES-128-ECB')

        cipher.encrypt
        cipher.key = key
        cipher.padding = 0

        plaintext = PKCS7.pad(plaintext) if opts[:padded]
        cipher.update(plaintext) + cipher.final
      end

      def decrypt(enc, key, opts = {})
        opts[:padded] = true if opts[:padded].nil?
        cipher = OpenSSL::Cipher.new('AES-128-ECB')

        cipher.decrypt
        cipher.key = key
        cipher.padding = 0

        plaintext = cipher.update(enc) + cipher.final
        opts[:padded] ? PKCS7.strip(plaintext) : plaintext
      end
    end
  end
end
