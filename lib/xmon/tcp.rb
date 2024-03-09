require "nmap/command"
require "nmap/xml"

module Xmon
  class TCP < Description
    def initialize(address, *args, **kwargs)
      @address = address
      @port = args[0]
      @protocol = kwargs[:protocol]
    end

    def key(type, value)
      @keys ||= []
      @keys << {type: type, value: value}
    end

    def fetch(host, ports, protocol = :tcp)
      File.delete("nmap.xml") if File.exist?("nmap.xml")
      Nmap::Command.new do |nmap|
        nmap.skip_discovery = true
        nmap.targets = host
        nmap.udp_scan = true if protocol == :udp
        nmap.ports = ports
        nmap.syn_scan = false
        nmap.service_scan = true
        nmap.verbose = 0
        nmap.output_xml = "nmap.xml"
      end.run_command
      Nmap::XML.open("nmap.xml") do |xml|
        @out = xml.hosts.map do |host|
          host.ports.map do |port|
            {
              host: host.ip,
              port: port.number,
              protocol: port.protocol,
              state: port.state
            }
          end
        end
      end
      @out.flatten
    end

    def check
      checker = fetch(@address, @port, :tcp)
      [Xmon.compare(@status, checker[0][:state])]
    end
  end
end
