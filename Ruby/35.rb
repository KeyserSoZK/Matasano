# Challenge 35: implement Diffie-Hellman with negotiated groups, and break it with malicious 'g' parameters.
#
# Structure mirrors 34_2.rb with necessary changes.
# Protocol difference from #34: the parameters (p, g) are negotiated in their own round-trip before the public keys are exchanged, so Mallory tampers 'g' during negotiation (rather than tampering pubkeys following negotiation).
#
# The challenge asks what occurs when g is set to an element of set {1, p, p - 1}.
# The answer is that the public keys (A = g^a mod p) are modified such that the shared session keys (s = A^b mod p) become predictable in each case:
#   1. g = 1:   `A = 1^a = 1 (mod p)` for any exponent/privkey, producing session key `s = A^b = 1^(ab) = 1 (mod p)`.
#   2. g = p:   `A = p^a = 0 (mod p)` for any exponent/privkey, producing session key `s = A^b = p^(ab) = 0 (mod p)`.
#   3. g = p-1: `A = (p-1)^a (mod p)` is either 1 or p-1 depending on a's parity (1 for even, p-1 for odd), producing session key `s = A^b = (p-1)^(ab) (mod p)` - which is p-1 only when a and b are both odd, else 1.

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

  def transmit(recipient, message)
    puts "#{@username} --[Sent]--> #{recipient.username}: #{message.inspect}."
    puts
  end

  def receive(sender, message)
    puts "#{@username} <--[Received]-- #{sender.username}: #{message.inspect}."
    puts
  end
end

class MITMProxy
  attr_reader :intercepted_messages

  def initialize
    @intercepted_messages = []
  end

  def transmit(sender, recipient, message, modified_message = message, type: nil)
    is_modified = modified_message != message

    log_intercepted({
      sender:           sender.username,
      recipient:        recipient.username,
      original_message: message,
      modified_message: modified_message,
      is_modified:      is_modified,
      type:             type,
    })

    sender.transmit(recipient, message)

    if is_modified
      puts "(** MITMProxy has modified the message! **)"
      puts
    end

    recipient.receive(sender, modified_message)
  end

  def log_intercepted(context = {})
    raise 'log_intercepted(): no context passed.' if context.empty?
    intercepted_messages << context
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

# Simulates the MITM attack via malicious 'g' injection during group negotiation.
def simulate_attack(malicious_g)
  alice   = EchoBot.new('Alice')
  bob     = EchoBot.new('Bob')
  mallory = MITMProxy.new  # Malicious middleman.

  # A->B: Send "p", "g". Mallory tampers g on the way through (to an element in set {1, p, p - 1}).
  original = [Diffie_Hellman::DEFAULT_P, Diffie_Hellman::DEFAULT_G]
  tampered = [Diffie_Hellman::DEFAULT_P, malicious_g]

  alice_dh = Diffie_Hellman.new(*tampered)
  mallory.transmit(alice, bob, original, tampered, type: :dh_params)
  bob_dh = Diffie_Hellman.new(*tampered)

  # B->A: Send ACK (Bob accepts the negotiated parameters).
  mallory.transmit(bob, alice, 'ACK', type: :ack)

  # Exchange pubkeys: A->B: Send "A", B->A: Send "B"
  mallory.transmit(alice, bob, alice_dh.public_key, type: :pubkey)
  mallory.transmit(bob, alice, bob_dh.public_key, type: :pubkey)

  # Derive session key on each side.
  alice_dh.set_session_key(bob_dh.public_key)
  bob_dh.set_session_key(alice_dh.public_key)

  # Alice and Bob exchange encrypted messages (with predictable session keys per malicious g).
  alice_msg     = 'Hola Bobby boy, how are ya bruz?'
  bob_msg       = "Yooo! Alice, my girl, you still ridin' those gnarly waves?"

  alice_msg_enc = Oracle::encrypt_message(alice_msg, alice_dh.session_key)
  bob_msg_enc   = Oracle::encrypt_message(bob_msg, bob_dh.session_key)

  mallory.transmit(alice, bob, alice_msg_enc, type: :ciphertext)
  mallory.transmit(bob, alice, bob_msg_enc, type: :ciphertext)

  # Mallory decrypts what went by:
  puts 'Communications complete. Decrypting.'
  puts

  ciphertexts = mallory.intercepted_messages.filter_map { |h| h[:original_message] if h[:type] == :ciphertext }

  # Mallory derives session key based on malicious g (each case in set {1, p, p - 1}):
  known_session_key = case malicious_g
                      when 1          then 1
                      when alice_dh.p then 0
                      when alice_dh.p - 1
                        both_odd = alice_dh.public_key == alice_dh.p - 1 && bob_dh.public_key == bob_dh.p - 1
                        both_odd ? alice_dh.p - 1 : 1
                      else
                        raise "simulate_attack(): known_session_key case not implemented."
                      end

  ciphertexts.each_with_index do |enc, i|
    puts "Decrypted message #{i + 1}: #{mallory_decrypt(enc, known_session_key)}"
  end
end

# Attacker's decryption routine. With a controllable g, the shared session key is predictable.
def mallory_decrypt(encrypted_message, known_session_key)
  known_aes_key = MatasanoLib::Digest::SHA1.digest(known_session_key.to_s)[0, 16]

  # The IV is appended to each ciphertext (Mallory has determined this and slices it off).
  iv                = encrypted_message.byteslice(-16..-1)
  encrypted_message = encrypted_message.byteslice(0...-16)

  MatasanoLib::AES_128.decrypt(encrypted_message, known_aes_key, iv: iv, mode: :CBC)
end

MALICIOUS_G_CASES = {
  '1'     => 1,
  'p'     => Diffie_Hellman::DEFAULT_P,
  'p - 1' => Diffie_Hellman::DEFAULT_P - 1
}

MALICIOUS_G_CASES.each do |label, malicious_g|
  puts "\n==== RUNNING ATTACK CASE g = #{label} ====\n\n"
  simulate_attack(malicious_g)
  puts
  puts '-' * 100
end

# # Output
# ------------------------------------------------------------------------------------------------------------------------------------------
# josh@Mac ~/Projects/Matasano/Ruby master !1 ?1
# ❯ ruby 35.rb
# ==== RUNNING ATTACK CASE g = 1 ====
#
# Alice --[Sent]--> Bob: [2410312426921032588552076022197566074856950548502459942654116941958108831682612228890093858261341614673227141477904012196503648957050582631942730706805009223062734745341073406696246014589361659774041027169249453200378729434170325843778659198143763193776859869524088940195577346119843545301547043747207749969763750084308926339295559968882457872412993810129130294592999947926365264059284647209730384947211681434464714438488520940127459844288859336526896320919633919, 2].
#
# (** MITMProxy has modified the message! **)
#
# Bob <--[Received]-- Alice: [2410312426921032588552076022197566074856950548502459942654116941958108831682612228890093858261341614673227141477904012196503648957050582631942730706805009223062734745341073406696246014589361659774041027169249453200378729434170325843778659198143763193776859869524088940195577346119843545301547043747207749969763750084308926339295559968882457872412993810129130294592999947926365264059284647209730384947211681434464714438488520940127459844288859336526896320919633919, 1].
#
# Bob --[Sent]--> Alice: "ACK".
#
# Alice <--[Received]-- Bob: "ACK".
#
# Alice --[Sent]--> Bob: 1.
#
# Bob <--[Received]-- Alice: 1.
#
# Bob --[Sent]--> Alice: 1.
#
# Alice <--[Received]-- Bob: 1.
#
# Alice --[Sent]--> Bob: "Xb:L\t\xA8h8\xDELo\x85\f/\xCC\xC2\x1FX\\L\a\x8F\xBD\xE4\x8F\x1D\xB9b!i\xFBF*\xBCw\xDB\xE9\x8F\xD4[$\xF5C\xEB\xCD\xEFA\xBF\x8C\xEE/\xF6d\xEC\x99\xEC3\x81\xF7\x7F@\xB1\x8C\xF2".
#
# Bob <--[Received]-- Alice: "Xb:L\t\xA8h8\xDELo\x85\f/\xCC\xC2\x1FX\\L\a\x8F\xBD\xE4\x8F\x1D\xB9b!i\xFBF*\xBCw\xDB\xE9\x8F\xD4[$\xF5C\xEB\xCD\xEFA\xBF\x8C\xEE/\xF6d\xEC\x99\xEC3\x81\xF7\x7F@\xB1\x8C\xF2".
#
# Bob --[Sent]--> Alice: "\x87\x94\xE8\x10\x00w3\xCA\"\x89p\xFDSI\n\xB6\xE7\xDEl2\x8C\\\xCB\xB0\xF6\xEDyh\xC3\xDF\x02\f\x8D\xAE\xAE\xF9a\xC4\x92X\xF0P\x90\xB6\x8A\xA4\xF0\xFE\xF3'\x14\x1DO\xAE\xDC\b\x82U\xF8\x1F\x11\xE3R\xB8\x8C\xD3fY);\"$p)\xE5\xAD\xEE\x18\x94\x96".
#
# Alice <--[Received]-- Bob: "\x87\x94\xE8\x10\x00w3\xCA\"\x89p\xFDSI\n\xB6\xE7\xDEl2\x8C\\\xCB\xB0\xF6\xEDyh\xC3\xDF\x02\f\x8D\xAE\xAE\xF9a\xC4\x92X\xF0P\x90\xB6\x8A\xA4\xF0\xFE\xF3'\x14\x1DO\xAE\xDC\b\x82U\xF8\x1F\x11\xE3R\xB8\x8C\xD3fY);\"$p)\xE5\xAD\xEE\x18\x94\x96".
#
# Communications complete. Decrypting.
#
# Decrypted message 1: Hola Bobby boy, how are ya bruz?
# Decrypted message 2: Yooo! Alice, my girl, you still ridin' those gnarly waves?
#
# ----------------------------------------------------------------------------------------------------
#
# ==== RUNNING ATTACK CASE g = p ====
#
# Alice --[Sent]--> Bob: [2410312426921032588552076022197566074856950548502459942654116941958108831682612228890093858261341614673227141477904012196503648957050582631942730706805009223062734745341073406696246014589361659774041027169249453200378729434170325843778659198143763193776859869524088940195577346119843545301547043747207749969763750084308926339295559968882457872412993810129130294592999947926365264059284647209730384947211681434464714438488520940127459844288859336526896320919633919, 2].
#
# (** MITMProxy has modified the message! **)
#
# Bob <--[Received]-- Alice: [2410312426921032588552076022197566074856950548502459942654116941958108831682612228890093858261341614673227141477904012196503648957050582631942730706805009223062734745341073406696246014589361659774041027169249453200378729434170325843778659198143763193776859869524088940195577346119843545301547043747207749969763750084308926339295559968882457872412993810129130294592999947926365264059284647209730384947211681434464714438488520940127459844288859336526896320919633919, 2410312426921032588552076022197566074856950548502459942654116941958108831682612228890093858261341614673227141477904012196503648957050582631942730706805009223062734745341073406696246014589361659774041027169249453200378729434170325843778659198143763193776859869524088940195577346119843545301547043747207749969763750084308926339295559968882457872412993810129130294592999947926365264059284647209730384947211681434464714438488520940127459844288859336526896320919633919].
#
# Bob --[Sent]--> Alice: "ACK".
#
# Alice <--[Received]-- Bob: "ACK".
#
# Alice --[Sent]--> Bob: 0.
#
# Bob <--[Received]-- Alice: 0.
#
# Bob --[Sent]--> Alice: 0.
#
# Alice <--[Received]-- Bob: 0.
#
# Alice --[Sent]--> Bob: "\x8D\xD3\xABs&\x11j\x98\xCB\xAA3\xE9\x8B\xFA\x94SU\xC5\xE1g\\\xE1\xFC}U\xFE\xFB1\xBD\x0F\x83\xD0\x1A=\xC7\xF5\xF7\x8F(\x05Cq\xCAj\x92\x89\xB1\xAB\x03-\xA5[.\xC8&\x92O-\xDBG\xB3,\xF9\xCE".
#
# Bob <--[Received]-- Alice: "\x8D\xD3\xABs&\x11j\x98\xCB\xAA3\xE9\x8B\xFA\x94SU\xC5\xE1g\\\xE1\xFC}U\xFE\xFB1\xBD\x0F\x83\xD0\x1A=\xC7\xF5\xF7\x8F(\x05Cq\xCAj\x92\x89\xB1\xAB\x03-\xA5[.\xC8&\x92O-\xDBG\xB3,\xF9\xCE".
#
# Bob --[Sent]--> Alice: "\xA8\xC4\xD9\x18\x9F\xCB1ty\x88\x98^\v\xCA\xC8\x92gJ\xD7\xC2X\x0F\xED\x1F\xB1\x0F\x17\xE0\xE9\x99\x05\x95\x1D\x10\xD8\xC1O\xBA\"\xA9\x8FK|\xF1\xAEh\xA6\x9A\xE0A\xF9\xF51\xCA\x1D\xD4\xE1\xBC\xF6\x9F\xF5\x921\x17\xD3\t\xB8\xDAt\xA3U\v\xF5\xB7\xF3\xFC)\xCCk\x05".
#
# Alice <--[Received]-- Bob: "\xA8\xC4\xD9\x18\x9F\xCB1ty\x88\x98^\v\xCA\xC8\x92gJ\xD7\xC2X\x0F\xED\x1F\xB1\x0F\x17\xE0\xE9\x99\x05\x95\x1D\x10\xD8\xC1O\xBA\"\xA9\x8FK|\xF1\xAEh\xA6\x9A\xE0A\xF9\xF51\xCA\x1D\xD4\xE1\xBC\xF6\x9F\xF5\x921\x17\xD3\t\xB8\xDAt\xA3U\v\xF5\xB7\xF3\xFC)\xCCk\x05".
#
# Communications complete. Decrypting.
#
# Decrypted message 1: Hola Bobby boy, how are ya bruz?
# Decrypted message 2: Yooo! Alice, my girl, you still ridin' those gnarly waves?
#
# ----------------------------------------------------------------------------------------------------
#
# ==== RUNNING ATTACK CASE g = p - 1 ====
#
# Alice --[Sent]--> Bob: [2410312426921032588552076022197566074856950548502459942654116941958108831682612228890093858261341614673227141477904012196503648957050582631942730706805009223062734745341073406696246014589361659774041027169249453200378729434170325843778659198143763193776859869524088940195577346119843545301547043747207749969763750084308926339295559968882457872412993810129130294592999947926365264059284647209730384947211681434464714438488520940127459844288859336526896320919633919, 2].
#
# (** MITMProxy has modified the message! **)
#
# Bob <--[Received]-- Alice: [2410312426921032588552076022197566074856950548502459942654116941958108831682612228890093858261341614673227141477904012196503648957050582631942730706805009223062734745341073406696246014589361659774041027169249453200378729434170325843778659198143763193776859869524088940195577346119843545301547043747207749969763750084308926339295559968882457872412993810129130294592999947926365264059284647209730384947211681434464714438488520940127459844288859336526896320919633919, 2410312426921032588552076022197566074856950548502459942654116941958108831682612228890093858261341614673227141477904012196503648957050582631942730706805009223062734745341073406696246014589361659774041027169249453200378729434170325843778659198143763193776859869524088940195577346119843545301547043747207749969763750084308926339295559968882457872412993810129130294592999947926365264059284647209730384947211681434464714438488520940127459844288859336526896320919633918].
#
# Bob --[Sent]--> Alice: "ACK".
#
# Alice <--[Received]-- Bob: "ACK".
#
# Alice --[Sent]--> Bob: 1.
#
# Bob <--[Received]-- Alice: 1.
#
# Bob --[Sent]--> Alice: 1.
#
# Alice <--[Received]-- Bob: 1.
#
# Alice --[Sent]--> Bob: "\xC9(\xD2\xD1\x8E\xA6\xE1\x1A\x12\xCEe\xEAqW=\xAAQ\x80C{RX\x1FC5\xB1\xB7E-Lu\xF3\x7F}\xFC\xF89\xE5p\x9A\x06x\x9E\"\"\x8A@#\x14X \x91\xF42!\x9E\xA5;\xC9=\x8E\xD9b\xD1".
#
# Bob <--[Received]-- Alice: "\xC9(\xD2\xD1\x8E\xA6\xE1\x1A\x12\xCEe\xEAqW=\xAAQ\x80C{RX\x1FC5\xB1\xB7E-Lu\xF3\x7F}\xFC\xF89\xE5p\x9A\x06x\x9E\"\"\x8A@#\x14X \x91\xF42!\x9E\xA5;\xC9=\x8E\xD9b\xD1".
#
# Bob --[Sent]--> Alice: "j\x9DF\x94\x12\xE9\xE5]\xBBG\x19\x7F\x82.\xF0#=J\xD4\xC9\xF4\a\x06]G\xECJ/('#|&\x04\xA7\x0F\xF6\xC7\xB60\xDF\xC95O1,\xE9\xE2 \x9A\x12;\r>u>]|\xAC\xC7[\xED<vH<\x113\xC5:\x0E\x00\x15Le3\x9E\xBBd\x99".
#
# Alice <--[Received]-- Bob: "j\x9DF\x94\x12\xE9\xE5]\xBBG\x19\x7F\x82.\xF0#=J\xD4\xC9\xF4\a\x06]G\xECJ/('#|&\x04\xA7\x0F\xF6\xC7\xB60\xDF\xC95O1,\xE9\xE2 \x9A\x12;\r>u>]|\xAC\xC7[\xED<vH<\x113\xC5:\x0E\x00\x15Le3\x9E\xBBd\x99".
#
# Communications complete. Decrypting.
#
# Decrypted message 1: Hola Bobby boy, how are ya bruz?
# Decrypted message 2: Yooo! Alice, my girl, you still ridin' those gnarly waves?
#
# ----------------------------------------------------------------------------------------------------
#
