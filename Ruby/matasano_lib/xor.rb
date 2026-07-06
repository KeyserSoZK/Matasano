require_relative 'monkey_patch'

module MatasanoLib
  module XOR
    class << self
      # Operates XOR on two hex strings, and returns the result in hex format.
      def hex(a, b)
        raise "Unequal buffers passed." if a.size != b.size
        (a.hex ^ b.hex).to_s(16)
      end

      # Return the number of set bits (the number of differing bits, as per XOR).
      def hamming_distance(a, b)
        raise "Unequal buffers passed." if a.length != b.length
        a.bytes.zip(b.bytes).map { |a, b| (a ^ b).to_s(2) }.join.count('1')
      end

      # Can be used for either encryption or decryption (as per the way XOR operates).
      def crypt(plaintext, key)
        ciphertext = ''

        plaintext.bytes.each_with_index do |byte, i|
          ciphertext << (byte ^ key.getbyte(i % key.length)).chr
        end

        ciphertext.to_hex
      end

      # Brute forces enc against charset: a 'scoring' function.
      # Returns a hash with the highest score.
      def brute_old(enc, charset)
        solution_data = {score: 0}

        # Splits up given charset (common characters) into a regular expression for comparison against resulting plaintexts.
        # 'ABC' => /A|B|C/i
        regexpr = Regexp.union(charset.chars)
        regexpr = Regexp.new(regexpr.source, Regexp::IGNORECASE)

        (0..255).each do |i|
          key_char  = i.chr
          xor_key   = (key_char * enc.length).to_hex  # Repeat single-key to match size of ciphertext for XOR'ing.
          dec_hex   = hex(enc.to_hex, xor_key)
          plaintext = dec_hex.unhex
          score     = plaintext.scan(regexpr).size / plaintext.length.to_f  # Returns the number of matches and normalises the result.

          # Update solution data to match more promising solution (higher score).
          if score > solution_data[:score]
            solution_data[:score]      = score
            solution_data[:key]        = key_char
            solution_data[:ciphertext] = enc.to_hex
            solution_data[:plaintext]  = plaintext
          end
        end

        #raise 'No solution.' if solution_data[:score] == 0
        solution_data
      end

      ENGLISH_FREQ = {
        'a'=>8.167, 'b'=>1.492, 'c'=>2.782, 'd'=>4.253, 'e'=>12.702,
        'f'=>2.228, 'g'=>2.015, 'h'=>6.094, 'i'=>6.966, 'j'=>0.153,
        'k'=>0.772, 'l'=>4.025, 'm'=>2.406, 'n'=>6.749, 'o'=>7.507,
        'p'=>1.929, 'q'=>0.095, 'r'=>5.987, 's'=>6.327, 't'=>9.056,
        'u'=>2.758, 'v'=>0.978, 'w'=>2.360, 'x'=>0.150, 'y'=>1.974,
        'z'=>0.074, ' '=>13.0, '.'=>1.0, ','=>1.0, "\n"=>1.0
      }

      def score_english(text)
        text.downcase.chars.sum do |c|
          if ENGLISH_FREQ.key?(c)
            ENGLISH_FREQ[c]
          elsif c.ord.between?(32, 126)
            0.0 # neutral score for valid but uncommon printable chars
          else
            -5.0 # strong penalty for non-printable/non-ASCII
          end
        end
      end

      def brute(enc)
        best = { score: -Float::INFINITY, key: nil, plaintext: nil }

        (0..255).each do |k|
          key_char  = k.chr
          xor_key   = key_char * enc.bytesize
          plaintext = enc.bytes.zip(xor_key.bytes).map { |a, b| (a ^ b).chr }.join
          score     = score_english(plaintext)

          if score > best[:score]
            best[:score] = score
            best[:key] = key_char
            best[:plaintext] = plaintext
          end
        end

        best
      end
    end
  end
end
