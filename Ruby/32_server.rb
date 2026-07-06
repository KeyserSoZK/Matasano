require 'sinatra'

require_relative 'matasano_lib/digest'

class Oracle
  HMAC_KEY = 'YELLOW SUBMARINE'

  def initialize(file)
    @hmac = MatasanoLib::Digest::SHA1_HMAC.hex_digest(HMAC_KEY, file)
  end

  def insecure_compare(signature)
    return false unless signature.bytesize == @hmac.bytesize

    # Validate HMAC signature with byte-at-a-time comparison (insecurely).
    @hmac.bytes.zip(signature.bytes).each do |b1, b2|
      return false if b1 != b2  # Exit early if bytes do not match (vulnerability part 1/2).
      sleep(0.0001)             # Artificial timing leak of 0.1ms (vulnerability part 2/2).
    end

    true  # Bytes match (artificial delay in effect).
  end
end

get '/test' do
  file, signature = params['file'], params['signature']

  oracle = Oracle.new(file)

  if oracle.insecure_compare(signature)
    status 200
    body '200 OK'
  else
    halt 500, '500 Internal Server Error'
  end
end
