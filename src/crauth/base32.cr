module Crauth
  module Base32
    extend self

    class Error < Exception; end

    PAD = '='.ord.to_u8

    DECODE_TABLE = Array(Int8).new(256) do |i|
      case i.chr
      when 'A'..'Z' then (i - 0x41).to_i8
      when '2'..'7' then (i - 0x18).to_i8
      else -1_i8
      end
    end

    def decode(data)
      slice = data.to_slice
      buffer = Pointer(UInt8).malloc(decode_size(slice.size))
      appender = buffer.appender
      from_base32(slice) { |byte| appender << byte }
      Slice.new(buffer, appender.size.to_i32)
    end

    private def decode_size(str_size)
      (str_size * 5 / 8.0).to_i + 8
    end

    private def from_base32(data)
      size = data.size
      dt = DECODE_TABLE.buffer
      cstr = data.pointer(size)
      while (size > 0) && (sym = cstr[size - 1]) && (sym == PAD)
        size -= 1
      end

      endcstr = cstr + size - 8

      while cstr <= endcstr
        quints = Array(Int8).new(8) { next_decoded_value }

        yield (quints[0] << 3 | quints[1] >> 2).to_u8
        yield ((quints[1] & 3) << 6 | quints[2] << 1 | quints[3] >> 4).to_u8
        yield ((quints[3] & 15) << 4 | quints[4] >> 1).to_u8
        yield ((quints[4] & 1) << 7 | quints[5] << 2 | quints[6] >> 3).to_u8
        yield ((quints[6] & 7) << 5 | quints[7]).to_u8
      end

      mod = (endcstr - cstr) % 8

      quints = Array(Int8).new(mod.to_i32) { next_decoded_value }

      if mod > 0
        yield (quints[0] << 3 | (mod > 1 ? quints[1] >> 2 : 0)).to_u8
      end

      if mod > 2
        yield ((quints[1] & 3) << 6 | quints[2] << 1 | (mod > 3 ? quints[3] >> 4 : 0)).to_u8
      end

      if mod > 3
        yield ((quints[3] & 15) << 4 | (mod > 4 ? quints[4] >> 1 : 0)).to_u8
      end

      if mod > 5
        yield ((quints[4] & 1) << 7 | quints[5] << 2 | (mod > 6 ? quints[6] >> 3 : 0)).to_u8
      end

      if mod > 6
        yield ((quints[6] & 7) << 5).to_u8
      end
    end

    macro next_decoded_value
      sym = cstr.value
      res = dt[sym.chr.upcase.ord]
      cstr += 1
      if res < 0
        raise Error.new("Unexpected symbol '#{sym.chr}'")
      end
      res
    end
  end
end
