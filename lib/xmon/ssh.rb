require "net/ssh"

module Xmon
  class SSH < TCP
    def initialize(parent, *args, **kwargs)
      @parent = parent
      @address = parent.address
      @port = args[0]
      @dsl_id = @port
      define_attributes([:version, :keys])
      super
    end

    def key(value)
      @keys ||= []
      @keys << value
    end

    def fetch(host, port = 22)
      s = Net::SSH::Transport::Session.new(host)
      {
        version: s.server_version.version,
        keys: s.host_keys.entries.map { |pkey| [Net::SSH::Buffer.from(:key, pkey).to_s].pack("m*").gsub(/\s/, "") }
      }
    end

    def check
      puts "checking SSH for #{@address} #{@host} #{@port}"
      current = fetch(@address, @port)
      r = []
      r << compare(:version, @version, current[:version]) if @version
      r << compare(:keys, @keys, current[:keys]) if @keys
      r
    end
  end
end
