# Challenge 35: implement Diffie-Hellman with negotiated groups, and break it with malicious 'g' parameters.
require 'securerandom'
require 'openssl'

require_relative 'matasano_lib/monkey_patch'
require_relative 'matasano_lib/digest'
require_relative 'matasano_lib/aes_128'

class Diffie_Hellman
  DEFAULT_G = 2
  DEFAULT_P = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff

  attr_reader :p, :g, :public_key, :session_key

  def initialize(p = DEFAULT_P, g = DEFAULT_G)
    @p = p
    @g = g
    @a = secure_random_bignum(@p + 1)

    # A = g^a mod p
    @public_key = mod_exp(@g, @a, @p)
  end

  def set_session_key(other_pubkey)
    raise 'set_session_key(other_pubkey) error: public key argument is invalid.' unless other_pubkey.is_a?(Integer)
    @session_key = mod_exp(other_pubkey, @a, @p)
  end

  private

  # @a = SecureRandom.rand(1...@p) would be okay for challenge purposes; but, for extremely large p's, it introduces bias (not uniformly distributed).
  # May as well do it right with OpenSSL::BN.
  def secure_random_bignum(max)
    OpenSSL::BN.rand_range(OpenSSL::BN.new(max.to_s)).to_i
  end

  # Implementation of the memory-efficient, fast modular exponentiation algorithm known as "exponentiation by squaring" (right-to-left binary method).
  # Computes `(base ** exp) % mod` (particularly useful for bignums).
  # NOTE: Ruby's pow() already does this as of version 2.5+, so this isn't needed. But I'll keep it for now.
  def mod_exp(base, exp, mod)
    return 0 if mod == 1

    result = 1
    base %= mod

    while exp > 0
      result = (result * base) % mod if exp.odd?

      exp >>= 1
      base = (base * base) % mod
    end

    result
  end
end

class EchoBot
  attr_reader :username

  def initialize(username)
    @username = username
  end

  def transmit(recipient_obj, message)
    puts "#{@username} -> #{recipient_obj.username}: #{message.inspect}."
    puts
  end
end

class MITMProxy
  attr_accessor :intercepted_msgs

  def initialize(sender, receiver, &interceptor)
    @sender      = sender
    @receiver    = receiver
    @interceptor = interceptor || proc { |msg| msg }

    @intercepted_msgs = []
  end

  def transmit(message)
    puts "#{@sender.username} --[intercepted]--> #{@receiver.username}."
    modified_message = @interceptor.call(message)
    @receiver.receive(modified_message, @sender)
  end

  def intercepted_msgs=(value)
    intercepted_msgs.push(value)
  end
end

class Oracle
  # AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
  def self.encrypt_message(message, dh_shared_key)
    key = derive_aes_key(dh_shared_key)
    iv  = SecureRandom.random_bytes

    MatasanoLib::AES_128.encrypt(message, key, iv: iv, mode: :CBC) + iv
  end

  # Generates the SHA-1 key used for AES later (AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv).
  # Consumes the DH session key.
  def self.derive_aes_key(dh_shared_key)
    dh_shared_key = dh_shared_key.to_s  # Convert to string for SHA-1 consumption, as it will be integer.
    MatasanoLib::Digest::SHA1.digest(dh_shared_key)[0, 16]
  end

  private_class_method :derive_aes_key
end

# Attacker's decryption routine based on knowledge of underlying algorithm and application of the key-fixing attack.
def mallory_decrypt(encrypted_message)
  # 'M should be able to decrypt the messages. "A" and "B" in the protocol -- the public keys, over the wire -- have been swapped out with "p".' 
  # 'Do the DH math on this quickly to see what that does to the predictability of the key.'

  # 'Decrypt the messages from M's vantage point as they go by.'

  # Since we have used parameter injection to set each public key to use the modulus p:
  #   `g^a mod p` becomes `p^a mod p`, which will always result to zero for any p per modulo exponentiation.
  # Hence, we reliably know that the session key s = 0 on both ends, and therefore the shared AES key is SHA1('0')[0:16] = unhex('b6589fc6ab0dc82cf12099d1c2d40ab9')
  known_session_key = '0'
  known_aes_key     = MatasanoLib::Digest::SHA1.digest(known_session_key)[0, 16]

  # We also know by protocol the IV is either appended or prepended. 
  # (Mallory has determined it is appended and taken them from the ciphertext.)
  iv = encrypted_message.byteslice(-16..-1)

  # Strip the IVs appended to each ciphertext in preparation for decryption.
  encrypted_message = encrypted_message.byteslice(0...-16)

  # Decrypt the message and return it.
  MatasanoLib::AES_128.decrypt(encrypted_message, known_aes_key, iv: iv, mode: :CBC)
end

# Simulates the MITM attack.
def simulate_attack
  alice   = EchoBot.new('Alice')
  bob     = EchoBot.new('Bob')
  mallory = EchoBot.new('Mallory')  # Malicious middleman.

  alice_dh = Diffie_Hellman.new
  bob_dh   = Diffie_Hellman.new(alice_dh.p, alice_dh.g)

  # A->B: Send "p", "g"
  alice.transmit(mallory, [alice_dh.p, alice_dh.g])
  alice_to_bob = MITMProxy.new(alice, bob) do |msg|
    p, _g
    # ...
  end

  # M->B: Relay "p", "g"
  mallory.transmit(bob, [alice_dh.p, alice_dh.g])

  # TODO: Maybe send to Mallory first for accuracy, but it honestly doesn't matter.
  # B->A
  bob.transmit(alice, 'ACK')

  bob_dh.set_session_key(alice_dh.p)

  # B->M: Send "B"
  # Note: this is also p per the key-fixing attack.
  bob.transmit(mallory, bob_dh.public_key)

  # M->A: Send "p"
  # Note: this is key-fixing aspect of the attack (on Alice).
  mallory.transmit(alice, bob_dh.p)   # Could also be alice_dh.p sent; doesn't matter here since p is the same. But this is logically consistent with key exchange.
  alice_dh.set_session_key(bob_dh.p)  # Could also be alice_dh.p sent; doesn't matter here since p is the same. But this is logically consistent with key exchange.

  raise 'Session key failure.' unless alice_dh.session_key == bob_dh.session_key

  # A->M: Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
  alice_msg     = 'Hola Bobby boy, how are ya bruz?'
  alice_msg_enc = Oracle::encrypt_message(alice_msg, alice_dh.session_key)

  alice.transmit(mallory, alice_msg_enc.to_hex)
  mallory_intercepted_msgs.push(alice_msg_enc)

  # M->B: Relay that to B
  mallory.transmit(bob, alice_msg_enc.to_hex)

  # B->M: Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
  # NOTE: I'm going to assume "A's msg" is actually meant to be B's message to A, as that is what makes sense.
  bob_msg     = "Yooo! Alice, my girl, you still ridin' those gnarly waves?"
  bob_msg_enc = Oracle::encrypt_message(bob_msg, bob_dh.session_key)

  bob.transmit(mallory, bob_msg_enc.to_hex)
  mallory_intercepted_msgs << bob_msg_enc

  # M->A: Relay that to A
  mallory.transmit(alice, bob_msg_enc.to_hex)

  # Commentary.
  puts 'Communications complete. Decrypting.'
  puts
  puts 'Mallory knows the shared session key is 0 due to g^a ≡ p^a ≡ 0 (mod p).'
  puts "Derived AES key from SHA-1('0')[0:16]: #{MatasanoLib::Digest::SHA1.digest('0')[0, 16].to_hex}"
  puts

  # Decrypt Alice and Bob's intercepted, encrypted messages.
  mallory_intercepted_msgs.each_with_index do |enc, i| 
    puts "Decrypted message #{i + 1}: #{mallory_decrypt(enc)}"
  end
end

simulate_attack
