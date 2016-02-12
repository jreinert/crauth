require "./hotp"

module Crauth
  class TOTP < HOTP
    def initialize(key : Slice(UInt8), @interval = 30)
      super(key)
    end

    def initialize(key : String, @interval = 30)
      super(key)
    end

    def generate
      generate(Time.now.epoch / @interval)
    end
  end
end
