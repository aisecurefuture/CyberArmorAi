# frozen_string_literal: true

# CyberArmor RASP — Ruby Runtime Application Self-Protection
# Supports: Rack middleware, Net::HTTP patch, Faraday middleware

require 'json'
require 'net/http'
require 'uri'

module CyberArmor
  module RASP
    AI_DOMAINS = %w[
      api.openai.com api.anthropic.com generativelanguage.googleapis.com
      api.cohere.ai api.mistral.ai api-inference.huggingface.co
      api.together.xyz api.replicate.com api.groq.com
    ].freeze

    PROMPT_INJECTION_PATTERNS = [
      /ignore\s+(all\s+)?previous\s+instructions/i,
      /you\s+are\s+now\s+(a|an|in)/i,
      /system\s*:\s*you\s+are/i,
      /<\s*(system|prompt|instruction)\s*>/i,
      /jailbreak|DAN\s+mode|bypass\s+filter/i,
    ].freeze

    DLP_PATTERNS = {
      ssn: /\b\d{3}-\d{2}-\d{4}\b/,
      credit_card: /\b4[0-9]{12}(?:[0-9]{3})?\b/,
      aws_key: /AKIA[0-9A-Z]{16}/,
      private_key: /-----BEGIN\s+(RSA|EC|PRIVATE)\s+KEY-----/,
    }.freeze

    class << self
      attr_accessor :config

      def configure
        self.config ||= Config.new
        yield(config) if block_given?
        config
      end

      def ai_endpoint?(host)
        clean = host.to_s.split(':').first.to_s
        AI_DOMAINS.include?(clean) ||
          clean.end_with?('.openai.azure.com') ||
          clean.end_with?('.cognitiveservices.azure.com')
      end

      def inspect_request(url, body = '')
        host = URI.parse(url).host rescue ''
        return InspectionResult.new(true) unless ai_endpoint?(host)

        # Prompt injection
        if config&.prompt_injection_enabled
          PROMPT_INJECTION_PATTERNS.each do |pat|
            if body.match?(pat)
              return InspectionResult.new(false, "Prompt injection: #{pat.source}") if config.mode == :block
            end
          end
        end

        # DLP
        if config&.dlp_enabled
          findings = DLP_PATTERNS.select { |_, pat| body.match?(pat) }.keys
          if findings.any?
            return InspectionResult.new(false, "Sensitive data: #{findings.join(',')}") if config.mode == :block
          end
        end

        InspectionResult.new(true)
      end
    end

    Config = Struct.new(:control_plane_url, :api_key, :tenant_id, :mode,
                         :dlp_enabled, :prompt_injection_enabled, :bootstrap_token, keyword_init: true) do
      def initialize(**)
        super
        self.control_plane_url ||= ENV.fetch('CYBERARMOR_CONTROL_PLANE_URL', ENV.fetch('CYBERARMOR_URL', 'http://localhost:8000'))
        self.api_key ||= ENV.fetch('CYBERARMOR_API_KEY', '')
        self.bootstrap_token ||= ENV.fetch('CYBERARMOR_BOOTSTRAP_TOKEN', '')
        self.tenant_id ||= ENV.fetch('CYBERARMOR_TENANT_ID', ENV.fetch('CYBERARMOR_TENANT', 'default'))
        self.mode ||= ENV.fetch('CYBERARMOR_MODE', 'monitor').to_sym
        self.dlp_enabled = true if dlp_enabled.nil?
        self.prompt_injection_enabled = true if prompt_injection_enabled.nil?
        redeem_bootstrap_token_if_needed
      end

      def redeem_bootstrap_token_if_needed
        return if bootstrap_token.to_s.empty? || !api_key.to_s.empty?

        uri = URI.join(control_plane_url.end_with?('/') ? control_plane_url : "#{control_plane_url}/", 'bootstrap/redeem')
        request = Net::HTTP::Post.new(uri)
        request['Content-Type'] = 'application/json'
        request.body = {
          bootstrap_token: bootstrap_token,
          package_key: 'rasp-ruby',
          subject_type: 'rasp_runtime',
          subject_name: ENV['CYBERARMOR_RASP_SUBJECT_NAME'] || ENV['HOSTNAME'] || 'ruby-rasp'
        }.to_json

        response = Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == 'https', read_timeout: 10, open_timeout: 10) do |http|
          http.request(request)
        end
        return unless response.is_a?(Net::HTTPSuccess)

        payload = JSON.parse(response.body)
        self.api_key = payload['api_key'] if payload['api_key']
        self.tenant_id = payload['tenant_id'] if payload['tenant_id']
      end
    end

    InspectionResult = Struct.new(:allowed, :reason) do
      def allowed?
        allowed
      end
    end

    # Rack Middleware
    class RackMiddleware
      def initialize(app)
        @app = app
        CyberArmor::RASP.configure unless CyberArmor::RASP.config
      end

      def call(env)
        if env['REQUEST_METHOD'] == 'POST'
          host = env['HTTP_X_FORWARDED_HOST'] || env['HTTP_HOST'] || ''
          if CyberArmor::RASP.ai_endpoint?(host)
            body = env['rack.input'].read
            env['rack.input'].rewind
            result = CyberArmor::RASP.inspect_request("https://#{host}#{env['PATH_INFO']}", body)
            unless result.allowed?
              return [403, { 'Content-Type' => 'application/json' },
                      [{ error: result.reason, policy: 'cyberarmor-rasp' }.to_json]]
            end
          end
        end
        @app.call(env)
      end
    end

    # Faraday Middleware
    class FaradayMiddleware < Faraday::Middleware
      def call(env)
        if env.method == :post
          host = env.url.host
          if CyberArmor::RASP.ai_endpoint?(host)
            body = env.body.to_s
            result = CyberArmor::RASP.inspect_request(env.url.to_s, body)
            unless result.allowed?
              raise "CyberArmor RASP blocked: #{result.reason}"
            end
          end
        end
        @app.call(env)
      end
    rescue NameError
      # Faraday not loaded
    end
  end
end

module CyberArmor
  RASP = CyberArmor::RASP
end
