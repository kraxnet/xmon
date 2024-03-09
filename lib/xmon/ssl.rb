module Xmon
  class SSL < TCP
    def initialize(parent, *args, **kwargs)
      @parent = parent
      @address = parent.address
      @dsl_id = @port
      define_attributes([:host, :status_code, :server, :cert_sn, :location])
      super
    end

    def dsl_id
      # [@port, @host, @path].join(":")
      [@port, @host].join(":")
    end

    def fetch(host, name = nil, port = 443, path = "/")
      ctx = OpenSSL::SSL::SSLContext.new
      sock = TCPSocket.new(host, port)
      ssl = OpenSSL::SSL::SSLSocket.new(sock, ctx)
      ssl.hostname = name if name
      ssl.sync_close = true
      ssl.connect
      cert = ssl.peer_cert
      request = "GET / HTTP/1.1\r\nHost: #{name}\r\nConnection: close\r\n\r\n"
      ssl.write request
      header = ssl.gets("\r\n\r\n")
      begin
        body = ssl.read
      rescue OpenSSL::SSL::SSLError
        body = ""
      end

      status, header = header.split("\r\n", 2)
      _protocol, status_code, _status_text = status.split(" ", 3)
      {
        cert_sn: cert.serial.to_s(16),
        status_code: status_code.to_i,
        headers: header.split("\r\n").map { |a| a.split(": ") }.to_h,
        body: body
      }
    end

    def check
      current = fetch(@address, @host, @port, @path)
      r = []
      r << compare(:status_code, @status_code, current[:status_code]) if @status_code
      r << compare(:server, @server, current.dig(:headers, "Server")) if @server
      r << compare(:cert_sn, @cert_sn, current[:cert_sn]) if @cert_sn
      r << compare(:location, @location, current.dig(:headers, "Location")) if @location
      r
    end
  end
end
