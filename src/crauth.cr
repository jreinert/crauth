require "./crauth/*"

module Crauth
  test = TOTP.new("vlzndkzbvazesvel")
  loop do
    puts test.generate
    sleep(30 - Time.now.second % 30)
  end
end
