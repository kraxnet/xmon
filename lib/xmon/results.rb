module Xmon
  class Results
    def self.add(result)
      @results ||= []
      @results << result
    end

    def self.get
      @results.flatten(1).select { |a| a.is_a?(Array) }
    end

    def self.print
      res = get
      resg = res.group_by(&:first)
      puts "Results"
      puts "-------"
      puts "Total: #{res.count}"
      puts "OK: #{resg[:ok].count}".colorize(:green) if resg[:ok]
      if resg[:fail]
        puts "FAIL: #{resg[:fail].count}".colorize(:red)
        puts "-------"
        resg[:fail].each do |r|
          puts "FAIL: #{r[1]} #{r[2]} != #{r[3]}".colorize(:red)
        end
      end
    end
  end
end
