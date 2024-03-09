module Xmon
  class Description
    attr_reader :parent

    def initialize
      @descriptions = []
    end

    def define_attributes(attributes)
      attributes.each do |m|
        self.class.send(:define_method, m) do |*args|
          if args[0]
            instance_variable_set(:"@#{m}", args[0])
          else
            instance_variable_get(:"@#{m}")
          end
        end
      end
    end

    def describe(*args, **kwargs, &)
      unless @description
        if kwargs[:type] == :domain
          @description = DomainDescription.new(args[0])
        elsif kwargs[:type] == :ipv4
          @description = IPv4Description.new(args[0])
        else
          puts "unknown block given with args: #{args} and kwargs: #{kwargs}"
          @description = Description.new
        end
      end

      if block_given?
        @description.instance_eval(&)
      else
        @description = @description.class.new(*args, **kwargs)
      end
      @descriptions ||= []
      @descriptions << @description
      @description = nil
    end

    def status(status) # standard:disable Style/TrivialAccessors
      @status = status
    end

    def check
      @results = []
      (@descriptions || []).each { |d|
        puts "#{d.class} #{@name}".colorize(:yellow)
        res = d.check
        @results << res

        Xmon.print_results([res])
      }
    end
  end

  class DomainDescription < Description
    attr_accessor :name

    def initialize(name, *)
      @name = name
    end

    def friendly_name
      @name
    end

    def describe(*args, **kwarg)
      if args == [:rdap]
        @description = Xmon::RDAP.new(self)
      elsif args == [:dns]
        @description = Xmon::DNS.new(self)
      end
      super
    end
  end

  class IPv4Description < Description
    attr_accessor :address
    def initialize(address, *)
      @address = address
    end

    def friendly_name
      @address
    end

    def describe(*, **kwargs)
      if kwargs[:type] == :tcp
        @description = if kwargs[:protocol] == :https
          Xmon::SSL.new(self, *, **kwargs)
        else
          Xmon::TCP.new(self, *, **kwargs)
        end
      elsif kwargs[:type] == :udp
        @description = Xmon::UDP.new(*, **kwargs)
      end
      super
    end

    def port(...)
      describe(...)
    end
  end
end
