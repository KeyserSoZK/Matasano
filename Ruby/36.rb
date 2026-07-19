# Challenge 36: implement Secure Remote Password (SRP).

require 'openssl'

module SRP
  # Same parameters from DH implementation: the 1536-bit MODP prime works fine as the N.
  N = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
  G = 2
  K = 3

  def self.secure_random_bignum(max)
    OpenSSL::BN.rand_range(OpenSSL::BN.new(max.to_s)).to_i
  end

  class Server
    def initialize
      @accounts = {}
      @sessions = {}
    end

    def register(email, password)
      salt = SRP.secure_random_bignum(N)
      x    = OpenSSL::Digest::SHA256.hexdigest(salt.to_s + password).to_i(16)
      v    = G.pow(x, N)

      @accounts[email] = { salt:, v: }
    end

    def login(email, bigA)
      account = @accounts.fetch(email) { raise "login(): unknown email #{email}." }

      v    = account[:v]
      b    = SRP.secure_random_bignum(N)
      bigB = (K * v + G.pow(b, N)) % N  # Challenge does not say to mod N final result, but RFC 5054 does (same result in any case).
      u    = OpenSSL::Digest::SHA256.hexdigest(bigA.to_s + bigB.to_s).to_i(16)
      bigS = (bigA * v.pow(u, N)).pow(b, N)

      @sessions[email] = OpenSSL::Digest::SHA256.digest(bigS.to_s)
      [account[:salt], bigB]
    end

    def verify(email, client_hmac)
      account     = @accounts.fetch(email) { raise "verify(): unknown email #{email}." }
      session_key = @sessions.fetch(email) { raise "verify(): session does not exist for #{email}." }

      client_hmac == OpenSSL::HMAC.hexdigest('SHA256', session_key, account[:salt].to_s)
    end
  end

  class Client
    def initialize(email, password)
      @email, @password = email, password
    end

    def authenticate(server)
      a    = SRP.secure_random_bignum(N)
      bigA = G.pow(a, N)

      salt, bigB = server.login(@email, bigA)

      u    = OpenSSL::Digest::SHA256.hexdigest(bigA.to_s + bigB.to_s).to_i(16)
      x    = OpenSSL::Digest::SHA256.hexdigest(salt.to_s + @password).to_i(16)
      bigS = (bigB - K * G.pow(x, N)).pow(a + u * x, N)

      @session_key = OpenSSL::Digest::SHA256.digest(bigS.to_s)
      hmac         = OpenSSL::HMAC.hexdigest('SHA256', @session_key, salt.to_s)

      server.verify(@email, hmac)
    end
  end
end

email, password = 'zero@cool.com', 'strongpassword123'

client = SRP::Client.new(email, password)
server = SRP::Server.new

server.register(email, password)

puts client.authenticate(server) ? 'OK' : 'You suck.'
puts SRP::Client.new(email, 'wrongpass').authenticate(server) ? 'OK (bugged)' : 'Rejected (good)'

# Output:
# ----------------
# ❯ ruby 36.rb
# OK
# Rejected (good)
