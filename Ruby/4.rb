# Challenge 4: detect single-character XOR cipher amongst a file of 60 possible ciphertexts.
# Additionally, let's break it. ;)

require_relative 'matasano_lib/url'
require_relative 'matasano_lib/xor'

def output_solution(solution = {}, opts = {})
  puts "Key: #{solution[:key]}"
  puts "Ciphertext: #{solution[:ciphertext]}"
  puts "Plaintext: #{solution[:plaintext]}"

  puts "Score: #{solution[:score]}" if opts[:with_score]
end

solution_data = {score: -Float::INFINITY}

MatasanoLib::URL.read_each_line('http://cryptopals.com/static/challenge-data/4.txt') do |line|
  temp = MatasanoLib::XOR.brute(line.unhex)
  temp[:ciphertext] = line  # The winning line's original hex ciphertext (for display).

  if temp[:score] > solution_data[:score]
    solution_data = temp
  end
end

output_solution(solution_data) unless solution_data.nil?

# Output:
# ------------------------------------------------------------------------
# Key: 5
# Ciphertext: 7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f
# Plaintext: Now that the party is jumping
# ------------------------------------------------------------------------
