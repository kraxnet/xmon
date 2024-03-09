module Xmon
  class UDP < Description
    def initialize(address, *args, **kwargs)
      @address = address
      @port = args[0]
      @protocol = kwargs[:protocol]
    end
  end
end
