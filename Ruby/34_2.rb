# Challenge 34 (other): implement a MITM key-fixing attack on Diffie-Hellman with parameter injection.
#
# Solution is functionally identical to the original. This version just implements an abstracted MITM layer (`MITMProxy` class) instead of a more-procedural flow.
# The original is likely easier to parse for understanding the attack, while this emulates a more realistic interceptor 'Malory' (though still without bothering with network sockets).

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

# Simulates the intended communication flow (no middleman).
# Note: unused / used for initial testing.
def simulate_intended
  alice   = EchoBot.new('Alice')
  bob     = EchoBot.new('Bob')

  alice_dh = Diffie_Hellman.new
  bob_dh   = Diffie_Hellman.new(alice_dh.p, alice_dh.g)

  # A->B: Send "p", "g", "A"
  alice.transmit(bob, [alice_dh.p, alice_dh.g, alice_dh.public_key])
  bob_dh.set_session_key(alice_dh.public_key)

  # B->A: Send "B"
  bob.transmit(alice, bob_dh.public_key)
  alice_dh.set_session_key(bob_dh.public_key)

  raise 'Session key failure.' unless alice_dh.session_key == bob_dh.session_key

  # A->B: Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
  alice_msg     = 'Hola Bobby boy, how are ya bruz?'
  alice_msg_enc = Oracle::encrypt_message(alice_msg, alice_dh.session_key)

  alice.transmit(bob, alice_msg_enc.to_hex)

  # B->A: Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
  bob_msg     = "Yooo! Alice, my girl, you still ridin' those gnarly waves?"
  bob_msg_enc = Oracle::encrypt_message(bob_msg, bob_dh.session_key)

  bob.transmit(alice, bob_msg_enc.to_hex)
end

# Simulates the MITM attack.
def simulate_attack
  alice   = EchoBot.new('Alice')
  bob     = EchoBot.new('Bob')
  mallory = MITMProxy.new  # Malicious middleman.

  alice_dh = Diffie_Hellman.new
  bob_dh   = Diffie_Hellman.new(alice_dh.p, alice_dh.g)

  # A->M: Send "p", "g", "A"
  # M->B: Send "p", "g", "p"
  # Note: this is key-fixing aspect of the attack (on Bob).
  original = [alice_dh.p, alice_dh.g, alice_dh.public_key]
  key_fix  = [original[0], original[1], original[0]]

  mallory.transmit(alice, bob, original, key_fix, type: :dh_params)

  # B->M: Send "B" (Note: this is also p per the key-fixing attack.)
  # M->A: Send "p"
  # Note: this is key-fixing aspect of the attack (on Alice).
  original = bob_dh.public_key
  key_fix  = bob_dh.p  # Could also be alice_dh.p sent; doesn't matter here since p is the same. But this is logically consistent with key exchange.

  mallory.transmit(bob, alice, original, key_fix, type: :dh_params)

  # Note: check for :type == :dh_params not strictly necessary here since it's already procedural.
  bob_last_received   = mallory.intercepted_messages.reverse_each.find { |h| h[:recipient] == 'Bob'   && h[:type] == :dh_params }
  alice_last_received = mallory.intercepted_messages.reverse_each.find { |h| h[:recipient] == 'Alice' && h[:type] == :dh_params }

  raise 'Error obtaining last dh_params message received for pubkey extraction.' unless alice_last_received && bob_last_received

  extract_last_param = ->(message) do
    value = message[:modified_message]
    value.is_a?(Array) ? value.last : value
  end

  alice_pubkey = extract_last_param.call(bob_last_received)
  bob_pubkey   = extract_last_param.call(alice_last_received)

  alice_dh.set_session_key(bob_pubkey)
  bob_dh.set_session_key(alice_pubkey)

  raise 'Session key failure.' unless alice_dh.session_key == bob_dh.session_key
  raise 'Key-fixing failure.'  unless alice_dh.session_key == 0 && bob_dh.session_key == 0

  # A->M: Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
  # M->B: Relay that to B
  alice_msg     = 'Hola Bobby boy, how are ya bruz?'
  alice_msg_enc = Oracle::encrypt_message(alice_msg, alice_dh.session_key)

  # NOTE: No longer pretty to_hex.
  mallory.transmit(alice, bob, alice_msg_enc, type: :ciphertext)

  # B->M: Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
  # M->A: Relay that to A
  # NOTE: I'm going to assume "A's msg" is actually meant to be B's message to A, as that is what makes sense.
  bob_msg     = "Yooo! Alice, my girl, you still ridin' those gnarly waves?"
  bob_msg_enc = Oracle::encrypt_message(bob_msg, bob_dh.session_key)

  # NOTE: No longer pretty to_hex.
  mallory.transmit(bob, alice, bob_msg_enc, type: :ciphertext)

  # Commentary.
  puts 'Communications complete. Decrypting.'
  puts
  puts 'Mallory knows the shared session key is 0 due to g^a ≡ p^a ≡ 0 (mod p).'
  puts "Derived AES key from SHA-1('0')[0:16]: #{MatasanoLib::Digest::SHA1.digest('0')[0, 16].to_hex}"
  puts

  # TODO: How to make this ciphertexts definition cleaner?
  ciphertexts = mallory.intercepted_messages.filter_map { |h| h[:original_message] if h[:type] == :ciphertext }
  ciphertexts.each_with_index do |enc, i|
    puts "Decrypted message #{i + 1}: #{mallory_decrypt(enc)}"
  end
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

simulate_attack

# 'Note that you don't actually have to inject bogus parameters to make this attack work; you could just generate Ma, MA, Mb, and MB as valid DH parameters to do a generic MITM attack.' 
# 'But do the parameter injection attack; it's going to come up again.'

# Output
# ------------------------------------------------------------------------------------------------------------------------------------------
# josh@lsd ~/Projects/Matasano/Ruby master !8 ?19                                                                                                                                                                                  08:22:43 PM
# ❯ ruby 34_2.rb
# Alice --[Sent]--> Bob: [2410312426921032588552076022197566074856950548502459942654116941958108831682612228890093858261341614673227141477904012196503648957050582631942730706805009223062734745341073406696246014589361659774041027169249453200378729434170325843778659198143763193776859869524088940195577346119843545301547043747207749969763750084308926339295559968882457872412993810129130294592999947926365264059284647209730384947211681434464714438488520940127459844288859336526896320919633919, 2, 827238774421677820107677454524550289688863305585727538203378545389032820041436097823400747240400329072934334578460991532051764492917909577139841501772474601024549257903936061197458322425486219409479825134412093137969645818149766106586688403921873266967732653660056305841560239554669719958570628218543281420487333132531436419630762036019714208097964780744777587870198687080098183010515364480974991571864876462323005118820559364845378551414995733276409378795492457].
# 
# (** MITMProxy has modified the message! **)
# 
# Bob <--[Received]-- Alice: [2410312426921032588552076022197566074856950548502459942654116941958108831682612228890093858261341614673227141477904012196503648957050582631942730706805009223062734745341073406696246014589361659774041027169249453200378729434170325843778659198143763193776859869524088940195577346119843545301547043747207749969763750084308926339295559968882457872412993810129130294592999947926365264059284647209730384947211681434464714438488520940127459844288859336526896320919633919, 2, 2410312426921032588552076022197566074856950548502459942654116941958108831682612228890093858261341614673227141477904012196503648957050582631942730706805009223062734745341073406696246014589361659774041027169249453200378729434170325843778659198143763193776859869524088940195577346119843545301547043747207749969763750084308926339295559968882457872412993810129130294592999947926365264059284647209730384947211681434464714438488520940127459844288859336526896320919633919].
# 
# Bob --[Sent]--> Alice: 1944572762552416803712274560890714721232718782088907566526871526897220022922197072846230665970318692467085749851614491770446826592405671663210637214054884674390587040331827078006547456539039669337301110021681433552544812812650966088915548071265992086727004415079237319004314182159110655730885002253571884134994292642294063005384146156936346912271240757541855369489993826130066363951683437863170064753677586259391690451489158649598226980424665925563524379811516743.
# 
# (** MITMProxy has modified the message! **)
# 
# Alice <--[Received]-- Bob: 2410312426921032588552076022197566074856950548502459942654116941958108831682612228890093858261341614673227141477904012196503648957050582631942730706805009223062734745341073406696246014589361659774041027169249453200378729434170325843778659198143763193776859869524088940195577346119843545301547043747207749969763750084308926339295559968882457872412993810129130294592999947926365264059284647209730384947211681434464714438488520940127459844288859336526896320919633919.
# 
# Alice --[Sent]--> Bob: "_7\xF1\xEC\xA0\xB3\x13\x9C<\xE9\xA6\x8A\\+qC\x8B\x96N\x9A\x14\xFD\xCD\xDC\xC2\f\a\x10M\x94\f\xB7\x103\b1\xD7\x05z\xE7\xDA\n\x9EB\t\x92(\xBF\xEAf\xA0\x969\x00\x18\x8EX\xA0\xF1\xBCP\xFD\xB1\xEE".
# 
# Bob <--[Received]-- Alice: "_7\xF1\xEC\xA0\xB3\x13\x9C<\xE9\xA6\x8A\\+qC\x8B\x96N\x9A\x14\xFD\xCD\xDC\xC2\f\a\x10M\x94\f\xB7\x103\b1\xD7\x05z\xE7\xDA\n\x9EB\t\x92(\xBF\xEAf\xA0\x969\x00\x18\x8EX\xA0\xF1\xBCP\xFD\xB1\xEE".
# 
# Bob --[Sent]--> Alice: "&\xC7\xCEg\xA7\xA4\xFFk\xD6\x8E\xFB\x86\x9B\x04\x89k$\xF2\x1E?\x1Dc\xDA\x85Z\xD13J\xFBE2\x92_\xA23\xC2\xC6\x8C\x89\xA5\x9E88X\x00!?\xA3q\xC2\xF8\xAB\x10\xEB\xF3\x93\xC3\x8B\x91J\x88\xAC\xB0\a\xCF\xC7\xEFm\x9F\x00\xA8_\xC0\xB4x\x1C\xD1\xC20\t".
# 
# Alice <--[Received]-- Bob: "&\xC7\xCEg\xA7\xA4\xFFk\xD6\x8E\xFB\x86\x9B\x04\x89k$\xF2\x1E?\x1Dc\xDA\x85Z\xD13J\xFBE2\x92_\xA23\xC2\xC6\x8C\x89\xA5\x9E88X\x00!?\xA3q\xC2\xF8\xAB\x10\xEB\xF3\x93\xC3\x8B\x91J\x88\xAC\xB0\a\xCF\xC7\xEFm\x9F\x00\xA8_\xC0\xB4x\x1C\xD1\xC20\t".
# 
# Communications complete. Decrypting.
# 
# Mallory knows the shared session key is 0 due to g^a ≡ p^a ≡ 0 (mod p).
# Derived AES key from SHA-1('0')[0:16]: b6589fc6ab0dc82cf12099d1c2d40ab9
# 
# Decrypted message 1: Hola Bobby boy, how are ya bruz?
# Decrypted message 2: Yooo! Alice, my girl, you still ridin' those gnarly waves?
