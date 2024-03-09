module Xmon
  class SSL < TCP
    def initialize(address, *args, **kwargs)
      @host = kwargs[:host]
      @path = kwargs[:path] || "/"
      define_attributes([:host, :status_code, :server, :cert_sn, :location])
      super
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
      puts "checking SSL for #{@address} #{@host} #{@port} #{@path}"
      current = fetch(@address, @host, @port, @path)
      r = []
      r << Xmon.compare(@status_code, current[:status_code]) if @status_code
      r << Xmon.compare(@server, current.dig(:headers, "Server")) if @server
      r << Xmon.compare(@cert_sn, current[:cert_sn]) if @cert_sn
      r << Xmon.compare(@location, current.dig(:headers, "Location")) if @location
      r
    end
  end
end
