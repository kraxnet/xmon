require "yaml"
require "fileutils"
require "cuid2"
require "netaddr"

module Xmon
  module Inventory
    class Generator
      attr_reader :inventory_dir

      def initialize(inventory_dir: ".")
        @inventory_dir = inventory_dir
      end

      def hostnames
        d = YAML.load(File.read(File.join(inventory_dir, "hostnames.yml")))
        FileUtils.mkdir_p("#{Page.output_dir}/hostnames")
        d.each do |entry|
          Page.new(entry["id"], "#{Page.output_dir}/hostnames").update(entry.merge("_type" => "hostname")).save
        end
      end

      def domains
        d = YAML.load(File.read(File.join(inventory_dir, "domains.yml")))
        FileUtils.mkdir_p("#{Page.output_dir}/domains")
        d.each do |entry|
          Page.new(entry["id"], "#{Page.output_dir}/domains").update(entry.merge("_type" => "domain")).save
        end
      end

      def ranges
        d = YAML.load(File.read(File.join(inventory_dir, "ip_ranges.yml")))
        FileUtils.mkdir_p("#{Page.output_dir}/ip_ranges")

        d.each do |entry|
          Page.new(entry["id"], "#{Page.output_dir}/ip_ranges").update(entry.merge("_type" => "ip_range")).save
        end

        Page.reload

        FileUtils.mkdir_p("#{Page.output_dir}/ipv4s")
        Page["ip_range"].each do |range|
          net = NetAddr::IPv4Net.parse(range["cidr"])
          (0...net.len).map { |i| net.nth(i).to_s }.each do |ip|
            page = Page.find { |p| p["_type"] == "ipv4" && p["ip"] == ip }
            page ||= Page.new(Cuid2.generate, "#{Page.output_dir}/ipv4s").update("_type" => "ipv4", "ip" => ip)
            page.update("ip_range" => range.id).save
          end
        end
      end

      def self.run(inventory_dir: ".")
        gen = new(inventory_dir: inventory_dir)
        gen.hostnames
        gen.domains
        gen.ranges
        Page.reload
      end
    end
  end
end
