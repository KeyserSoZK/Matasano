require_relative 'monkey_patch'

module MatasanoLib
  module XOR
    class << self
      # Operates XOR on two hex strings, and returns the result in hex format.
      # Left-pad to the input width so a result with a leading zero nibble isn't truncated.
      def hex(a, b)
        raise "Unequal buffers passed." if a.size != b.size
        (a.hex ^ b.hex).to_s(16).rjust(a.size, '0')
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

      # Brute forces single-byte XOR against `enc` (a raw byte string), scoring each candidate
      # plaintext with `score_english`. Returns the highest-scoring { score:, key:, plaintext: }.
      # `key` is the single key byte as a 1-character string.
      def brute(enc)
        best = { score: -Float::INFINITY, key: nil, plaintext: nil }

        (0..255).each do |k|
          plaintext = enc.bytes.map { |b| (b ^ k).chr }.join
          score     = score_english(plaintext)

          if score > best[:score]
            best[:score]     = score
            best[:key]       = k.chr
            best[:plaintext] = plaintext
          end
        end

        best
      end
    end
  end
end
