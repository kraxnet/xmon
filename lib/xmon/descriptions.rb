module Xmon
  class Description
    attr_reader :parent, :dsl_id

    def path
      [@parent ? @parent.path : nil, self.class.to_s.split("::").last, dsl_id].compact.join("/")
    end

    def friendly_name
      [path, dsl_id].join("/")
    end

    def compare(name, a, b)
      info = [path, name].join("/")
      if a == b
        [:ok, info, a].compact
      else
        [:fail, info, a, b].compact
      end
    end

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

    def domain(name, &)
      @description = DomainDescription.new(name)
      describe(&)
    end

    def ipv4(address, &)
      @description = IPv4Description.new(address)
      describe(&)
    end

    def describe(*args, **kwargs, &)
      unless @description
        puts "unknown block given with args: #{args} and kwargs: #{kwargs}"
        exit
      end

      if block_given?
        @description.instance_eval(&)
      else
        #  @description = @description.class.new(*args, **kwargs)
      end
      @descriptions ||= []
      @descriptions << @description
      @description = nil
    end

    def status(status) # standard:disable Style/TrivialAccessors
      @status = status
    end

    def check
      (@descriptions || []).each { |d|
        puts "#{d.class} #{@name}".colorize(:yellow)
        res = d.check
        Xmon::Results.add(res)
        Xmon.print_results([res])
      }
    end
  end

  class DomainDescription < Description
    attr_accessor :name

    def initialize(name, *)
      @name = name
      @dsl_id = name
    end

    def rdap(&)
      @description = Xmon::RDAP.new(self)
      describe(&)
    end

    def dns(&)
      @description = Xmon::DNS.new(self)
      describe(&)
    end

    def whois(&)
      @description = Xmon::Whois.new(self)
      describe(&)
    end
  end

  class IPv4Description < Description
    attr_accessor :address
    def initialize(address, *)
      @address = address
      @dsl_id = address
    end

    def ptr(*, **, &)
      @description = Xmon::ReverseDNS.new(self, *, **)
      describe(&)
    end

    def udp(*, **, &)
      @description = Xmon::UDP.new(self, *, **)
      describe(&)
    end

    def tcp(*, **, &)
      @description = Xmon::TCP.new(self, *, **)
      describe(&)
    end

    def https(*, **, &)
      @description = Xmon::SSL.new(self, *, **)
      describe(&)
    end

    def ssh(*, **, &)
      @description = Xmon::SSH.new(self, *, **)
      describe(&)
    end

    def port(...)
      describe(...)
    end
  end
end
