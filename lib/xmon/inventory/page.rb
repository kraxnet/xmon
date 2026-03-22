require "yaml"
require "fileutils"

module Xmon
  module Inventory
    class Page
      attr_accessor :id, :bucket, :frontmatter, :content

      def initialize(id, bucket = "output")
        @id = id
        @bucket = bucket
        try_to_load
      end

      def [](key)
        @frontmatter[key.to_s]
      end

      def path_for(id)
        "#{bucket}/#{id}.md"
      end

      def try_to_load
        if File.exist?(path_for(@id))
          raw = File.read(path_for(@id))
          if raw =~ /^(---\s*\n.*?\n?)^(---\s*$\n?)(.*)/m
            @frontmatter = YAML.load($1)
            @content = $3
          else
            raise "No frontmatter in #{path_for(@id)}"
          end
        else
          @frontmatter = {}
          @content = ""
        end
      end

      def update(data)
        @frontmatter.merge!(data.map { |k, v| [k.to_s, v] }.to_h)
        self
      end

      def save
        File.open(path_for(@id), "w") do |f|
          f.puts @frontmatter.to_yaml
          f.puts "---"
          f.puts @content
        end
      end

      class << self
        def output_dir
          @output_dir || "output"
        end

        def output_dir=(dir)
          @output_dir = dir
          reload
        end

        def [](key)
          all.select { |page| page["_type"] == key }
        end

        def all
          @@all ||= Dir.glob("#{output_dir}/**/*.md").map { |file|
            Page.new(File.basename(file, ".md"), File.dirname(file))
          }
        end

        def find(&block)
          all.find(&block)
        end

        def reload
          @@all = nil
        end
      end
    end
  end
end
