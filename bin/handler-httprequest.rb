#!/usr/bin/env ruby
#
#   handler-httprequest.rb
#
# DESCRIPTION:
#
# OUTPUT:
#   json, www-form
#
# PLATFORMS:
#   Linux, BSD, Solaris
#
# DEPENDENCIES:
#   gem: sensu-plugin
#
# USAGE:
#
# NOTES:
#
# LICENSE:
#   Joachim Jabs
#   Released under the same terms as Sensu (the MIT license); see LICENSE
#   for details.
#

require 'net/http'
require 'sensu-handler'
require 'erb'
require 'timeout'
require 'json'
require 'uri'
require 'mixlib/cli'
require 'ostruct'


class HttpRequest < Sensu::Handler
  include Mixlib::CLI
  
  option :json_config,
    description: 'Configuration name',
    short: '-j JSONCONFIG',
    long: '--json JSONCONFIG',
    default: 'httprequest'

  def handle

    requests = HttpRequest::Config.new(settings[config[:json_config]], @event)
    # Maybe async for multiple items?
    requests.list.each do | task |
      HttpRequest::Task.new(task)
    end

  end
  
  # Small helpers. 
  class Config
    
    def initialize(config, event)
      @config_list = Array.new
      config_item = validate(defaults.merge(config))
      @config_list.push(config_item) unless config_item.nil?
      if config.has_key?('subscriptions') && event['client'].has_key?('subscriptions')
        event['client']['subscriptions'].each do | subscription_config |
          if config['subscriptions'].has_key?(subscription_config) && 
              config_item = validate(defaults.merge(config['subscriptions'][subscription_config]))
              @config_list.push(config_item) unless config_item.nil?
          end
        end
      end    
    end
    
    def list
      @config_list
    end
    
    def defaults
      {
        "method" => "Post",
        "url" => "",
        "body_template" => "",
        "body" => {},
        "header_template" => "",
        "header" => {},
        "params_template" => "",
        "params" => "",
        "client_cert" => "",
        "ca_cert" => "",
        "client_key" => "",
        "username" => "",
        "password" => ""
      }
    end

    def validate(config) 
      valid_config = Hash.new
      @basic_auth = false
      @use_ssl = false
      # Preflight checks
      ["url_config", "method_config", "exclusives", "dependend"].each do | preflight |
        unless self.send("validate_#{preflight}", config)
          return
        end
      end
      defaults.each_key do | key |
        if ! config[key].empty? && ! key.to_s.include?("username") && ! key.to_s.include?("password")
          valid_config[key] = self.send("validate_#{key}", config[key])
          if ! valid_config[key]
            return
          end
        end
      end
      # Make it more uniform
      ["body", "header", "params"].each do | content |
        unless valid_config["#{content}_template"].nil? || valid_config["#{content}_template"].empty? 
          valid_config[content] = valid_config["#{content}_template"]
          valid_config.delete("#{content}_template")
        end
      end
      # required for ostruct since method is already a ruby base method
      valid_config['request_method'] = valid_config.delete('method') 
      valid_config['basic_auth'] = @basic_auth
      valid_config['use_ssl'] = @use_ssl
      return OpenStruct.new(valid_config)
    end
        
    ### Preflight Validations ###
    private
    def validate_url_config(config)
      # This is not really a problem since a config can only have subscriptions.
      if config.has_key?('url') && config['url'].empty?
        return false
      end
      return true
    end
    
    def validate_method_config(config)
      if config['method'].empty?
        puts "Key \"method\" defined but empty. Valid request methods: #{valid_request_methods.join(" ")}"
        return false
      end
      return true
    end
    
    def validate_dependend(config)
      fail_count = 0
      ["username", "password"].each do | element |
        if config[element].empty?
          fail_count += 1
        end
      end
      case fail_count
        when 0
          @basic_auth = true
        when 1
          puts "Username or Password must both be specified or not at all"
          return false
      end
      return true
    end
    
    ### Config validations ###
    def valid_request_methods
      valid_request_methods = [
        'Get',
        'Head',
        'Post',
        'Patch',
        'Put',
        'Options',
        'Delete'
      ]
    end
    
    def validate_exclusives(config)
      ["body", "header", "params"].each do | element |        
        if ! config["#{element}_template"].empty? && ! config[element].empty?
          puts "the keys #{element}_template and #{element} are exclusive."
          return false
        end
      end
      return true
    end
    
    def validate_method(method)
      # Todo return that class constant maybe?
      unless valid_request_methods.include?(method.capitalize)
        puts "Invalid request method #{method.capitalize}. Valid request methods: #{valid_request_methods.join(" ")}"
        return false
      end
      return "Net::HTTP::#{method.capitalize}".split('::').inject(Object) {|o,c| o.const_get c}
    end
    
    def validate_url(url)
      valid_url = URI.parse(url)
      # Only accept http/https? 
      @use_ssl = true if valid_url.scheme == 'https'
      return valid_url
    rescue
      puts "Configured URL #{url} is not valid"
      return false
    end
    
    # Is this OK?
    def validate_content_template(template)
      return validate_content(JSON.parse(ERB.new(File.read(template)).result))
    rescue StandardError => e
      puts "Configuration or template error: #{e.message}"
      return false
    end
    
    # Is this OK too?
    def validate_content(content)
      if content.respond_to?(:each_pair)
        return content
      else
        puts "content is not in a valid format: #{content}"
        return false
      end
    end
        
    def validate_certs(certificate)
    ### stub - certifcate handling not implemented yet ###
      return certificate
    end
    
    ### Aliases must be set at the end of the class. Maybe because its interpreted... ###
    alias_method :validate_body, :validate_content
    alias_method :validate_body_template, :validate_content_template
    alias_method :validate_header, :validate_content
    alias_method :validate_header_template, :validate_content_template
    alias_method :validate_params, :validate_content
    alias_method :validate_params_template, :validate_content_template
    alias_method :validate_ca_cert, :validate_certs
    alias_method :validate_client_cert, :validate_certs
    alias_method :validate_client_key, :validate_certs    
  end
  
  class Task
    
    def initialize(task)
      # TODO: SSL certificate handling
      puts task
      @uri = task.url
      @uri.query = URI.encode_www_form(task.params) unless task.params.nil? || task.params.empty?
      @request = "" 
      request_constructor(task)
      puts @request
      
      begin
        http_conn = Net::HTTP.start(@uri.host, @uri.port, :use_ssl => task.use_ssl)
        response = http_conn.request(@request)
        puts response.message
        http_conn.finish
      rescue StandardError => e
        puts "something went wrong: #{e.message}"
      end      

    end
    
    # Could be nicer
    def request_constructor(task)
      puts task.header.nil?
      if ! task.header.nil? #|| ! task.header.empty?
        if task.header.has_key?('Content-Type') && task.header['Content-Type'].include?("json")
          @request = task.request_method.new(@uri, task.header)
          @request.body = task.body.to_json unless task.body.nil? || task.body.empty?
          
        else
          @request = task.request_method.new(@uri.request_uri, task.header)
          construct_form_body(task.body) unless task.body.nil? || task.body.empty?
        end
      else
        # Sets a default header anyway: application/x-www-form-urlencoded 
        @request = task.request_method.new(@uri.request_uri)
        construct_form_body(task.body) unless task.body.nil? || task.body.empty?
      end
      @request.basic_auth task.username.to_s, task.password.to_s if task.basic_auth
    end
 
    def construct_form_body(body_content)
      @request.set_form_data(body_content)
    end

  end
  
end
