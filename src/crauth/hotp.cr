require "openssl/hmac"
require "./base32"

module Crauth
  class HOTP
    def initialize(@key : Slice(UInt8))
    end

    def initialize(key : String)
      initialize(Base32.decode(key))
    end

    def generate(counter)
      counter = counter.to_i64
      counter_slice = (pointerof(counter) as UInt8[8]*).value.reverse!.to_slice
      hash = OpenSSL::HMAC.digest(:sha1, @key, counter_slice)
      value = truncate(hash)
      sprintf("%06d", value % 1_000_000)
    end

    private def truncate(slice)
      offset = slice[19] & 0x0f_u8
      0_u32 | (slice[offset] & 0x7f_u8).to_u32 << 24 |
               slice[offset + 1].to_u32        << 16 |
               slice[offset + 2].to_u32        <<  8 |
               slice[offset + 3].to_u32
    end
  end
end
