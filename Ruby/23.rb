# Challenge 23: clone an MT19937 RNG from its output.

# The internal state of MT19937 consists of 624 32-bit integers.
# For each batch of 624 outputs, MT permutes that internal state. By permuting state regularly, MT19937 achieves a period of 2**19937, which is big.
# 
# Each time MT19937 is tapped, an element of its internal state is subjected to a tempering function that diffuses bits through the result.
# The tempering function is invertible; you can write an "untemper" function that takes an MT19937 output and transforms it back into the corresponding element of the MT19937 state array.
# 
# To invert the temper transform, apply the inverse of each of the operations in the temper transform in reverse order.
# There are two kinds of operations in the temper transform each applied twice; one is an XOR against a right-shifted value, and the other is an XOR against a left-shifted value AND'd with a magic number.
# So, you'll need code to invert the "right" and the "left" operation.
# 
# Once you have "untemper" working, create a new MT19937 generator, tap it for 624 outputs, untemper each of them to recreate the state of the generator, and splice that state into a new instance of the MT19937 generator.
# 
# The new "spliced" generator should predict the values of the original.

require_relative 'matasano_lib/mt19937'

def clone_mt19937(mt)
  mt_clone = MatasanoLib::MT19937.new(0).tap do |clone|
    624.times do |i|
      clone.state[i] = mt.untemper(mt.extract_number)
    end
  end
end

mt_rand       = MatasanoLib::MT19937.new(0x1337)
mt_rand_clone = clone_mt19937(mt_rand)

# Test clone was successful.
10_000.times do
  raise 'MT19937 cloning failed!' unless mt_rand.extract_number == mt_rand_clone.extract_number
end

puts 'Winner! Here, have a few:'
puts

10.times do
  printf("[%s, %10s]\n", mt_rand.extract_number, mt_rand_clone.extract_number)
end

# Output
# ------------------------------------------------------------------------------------
# [josh@purehacking] [/dev/ttys005] [master ⚡] [~/Projects/Matasano/Ruby]> ruby 23.rb
# Winner! Here, have a few:
# 
# [3720904052, 3720904052]
# [3576649650, 3576649650]
# [919419452,  919419452]
# [1642496979, 1642496979]
# [2885456077, 2885456077]
# [1232031229, 1232031229]
# [3674379477, 3674379477]
# [2588028296, 2588028296]
# [1429259843, 1429259843]
# [1799426814, 1799426814]
