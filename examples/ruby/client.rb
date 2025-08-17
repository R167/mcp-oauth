#!/usr/bin/env ruby
# frozen_string_literal: true

require 'net/http'
require 'uri'
require 'json'
require 'base64'
require 'digest'
require 'securerandom'
require 'jwt'
require 'openssl'

# MCP OAuth Client for Ruby
# Handles OAuth 2.1 flow with PKCE for MCP resources
class MCPOAuthClient
  attr_reader :client_id, :base_url, :redirect_uri, :scope

  def initialize(client_id, base_url, redirect_uri, scope)
    @client_id = client_id
    @base_url = base_url
    @redirect_uri = redirect_uri
    @scope = scope
    @http_timeout = 30
  end

  # Register client with OAuth server (dynamic client registration)
  def self.register_client(base_url, client_name, redirect_uris, scope)
    uri = URI("#{base_url}/register")
    
    request_data = {
      client_name: client_name,
      redirect_uris: redirect_uris,
      scope: scope
    }
    
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = uri.scheme == 'https'
    http.read_timeout = 30
    
    request = Net::HTTP::Post.new(uri.path)
    request['Content-Type'] = 'application/json'
    request.body = request_data.to_json
    
    response = http.request(request)
    
    unless response.code == '201'
      raise "Client registration failed: #{response.body}"
    end
    
    JSON.parse(response.body, symbolize_names: true)
  end

  # PKCE challenge and verifier generation
  def generate_pkce
    code_verifier = Base64.urlsafe_encode64(SecureRandom.random_bytes(32), padding: false)
    code_challenge = Base64.urlsafe_encode64(
      Digest::SHA256.digest(code_verifier),
      padding: false
    )
    
    {
      code_verifier: code_verifier,
      code_challenge: code_challenge
    }
  end

  # Build OAuth authorization URL
  def authorization_url(state, pkce)
    params = {
      response_type: 'code',
      client_id: @client_id,
      redirect_uri: @redirect_uri,
      scope: @scope,
      state: state,
      code_challenge: pkce[:code_challenge],
      code_challenge_method: 'S256'
    }
    
    query_string = params.map { |k, v| "#{k}=#{URI.encode_www_form_component(v)}" }.join('&')
    "#{@base_url}/authorize?#{query_string}"
  end

  # Exchange authorization code for tokens
  def exchange_code_for_tokens(code, pkce)
    uri = URI("#{@base_url}/token")
    
    form_data = {
      grant_type: 'authorization_code',
      code: code,
      redirect_uri: @redirect_uri,
      client_id: @client_id,
      code_verifier: pkce[:code_verifier]
    }
    
    response = make_token_request(uri, form_data)
    parse_token_response(response)
  end

  # Refresh access token using refresh token
  def refresh_tokens(refresh_token)
    uri = URI("#{@base_url}/token")
    
    form_data = {
      grant_type: 'refresh_token',
      refresh_token: refresh_token,
      client_id: @client_id
    }
    
    response = make_token_request(uri, form_data)
    parse_token_response(response)
  end

  private

  def make_token_request(uri, form_data)
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = uri.scheme == 'https'
    http.read_timeout = @http_timeout
    
    request = Net::HTTP::Post.new(uri)
    request['Content-Type'] = 'application/x-www-form-urlencoded'
    request.body = URI.encode_www_form(form_data)
    
    response = http.request(request)
    
    unless response.is_a?(Net::HTTPSuccess)
      raise "Token request failed: #{response.code} #{response.body}"
    end
    
    response
  end

  def parse_token_response(response)
    data = JSON.parse(response.body)
    
    {
      access_token: data['access_token'],
      refresh_token: data['refresh_token'],
      token_type: data['token_type'],
      expires_in: data['expires_in']
    }
  rescue JSON::ParserError => e
    raise "Failed to parse token response: #{e.message}"
  end
end

# JWT Token Validator for MCP Resource Servers
class MCPTokenValidator
  def initialize(jwks_url, issuer, audience)
    @jwks_url = jwks_url
    @issuer = issuer
    @audience = audience
    @jwks_cache = nil
    @cache_expiry = nil
    @http_timeout = 10
  end

  # Validate JWT access token
  def validate_token(token_string)
    # Fetch JWKS if not cached or expired
    fetch_jwks_if_needed
    
    # Decode and verify token
    decoded_token = JWT.decode(
      token_string,
      nil,
      true,
      {
        algorithms: ['RS256'],
        iss: @issuer,
        aud: @audience,
        verify_iss: true,
        verify_aud: true,
        verify_expiration: true,
        jwks: @jwks_cache
      }
    )
    
    payload = decoded_token[0]
    
    # Validate token type
    unless payload['token_type'] == 'access'
      raise "Invalid token type: expected 'access', got '#{payload['token_type']}'"
    end
    
    {
      user_id: payload['sub'],
      scope: payload['aud'],
      email: payload['email'],
      expires_at: Time.at(payload['exp'])
    }
  rescue JWT::DecodeError => e
    raise "Token validation failed: #{e.message}"
  end

  private

  def fetch_jwks_if_needed
    now = Time.now
    
    # Fetch if no cache or cache expired (cache for 1 hour)
    if @jwks_cache.nil? || (@cache_expiry && now > @cache_expiry)
      fetch_jwks
      @cache_expiry = now + 3600 # 1 hour
    end
  end

  def fetch_jwks
    uri = URI(@jwks_url)
    
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = uri.scheme == 'https'
    http.read_timeout = @http_timeout
    
    response = http.get(uri)
    
    unless response.is_a?(Net::HTTPSuccess)
      raise "Failed to fetch JWKS: #{response.code} #{response.body}"
    end
    
    jwks_data = JSON.parse(response.body)
    
    # Convert JWKS to format expected by ruby-jwt
    @jwks_cache = {
      keys: jwks_data['keys'].map do |key|
        {
          kid: key['kid'],
          kty: key['kty'],
          use: key['use'],
          n: key['n'],
          e: key['e']
        }
      end
    }
  rescue JSON::ParserError => e
    raise "Failed to parse JWKS response: #{e.message}"
  end
end

# Token Manager - handles token storage and automatic refresh
class MCPTokenManager
  def initialize(oauth_client, storage = nil)
    @oauth_client = oauth_client
    @storage = storage || SimpleTokenStorage.new
    @refresh_threshold = 300 # Refresh when less than 5 minutes remaining
  end

  # Get valid access token, refreshing if necessary
  def get_access_token
    tokens = @storage.load_tokens
    return nil unless tokens

    # Check if token needs refresh
    if token_needs_refresh?(tokens)
      refresh_and_store_tokens(tokens[:refresh_token])
    else
      tokens[:access_token]
    end
  end

  # Store initial tokens after OAuth flow
  def store_tokens(tokens)
    token_data = {
      access_token: tokens[:access_token],
      refresh_token: tokens[:refresh_token],
      expires_at: Time.now + tokens[:expires_in]
    }
    
    @storage.save_tokens(token_data)
  end

  # Clear stored tokens
  def clear_tokens
    @storage.clear_tokens
  end

  private

  def token_needs_refresh?(tokens)
    return true unless tokens[:expires_at]
    
    Time.now >= (tokens[:expires_at] - @refresh_threshold)
  end

  def refresh_and_store_tokens(refresh_token)
    new_tokens = @oauth_client.refresh_tokens(refresh_token)
    store_tokens(new_tokens)
    new_tokens[:access_token]
  rescue => e
    # If refresh fails, clear tokens and re-raise
    clear_tokens
    raise e
  end
end

# Simple in-memory token storage (replace with persistent storage in production)
class SimpleTokenStorage
  def initialize
    @tokens = nil
  end

  def save_tokens(tokens)
    @tokens = tokens
  end

  def load_tokens
    @tokens
  end

  def clear_tokens
    @tokens = nil
  end
end

# Example usage for MCP client
def example_oauth_client
  puts "=== MCP OAuth Client Example ==="
  
  puts "Step 1: Register OAuth Client"
  
  # Register client with the OAuth server
  begin
    registration = MCPOAuthClient.register_client(
      'https://auth.mcp.r167.dev',
      'My Ruby MCP Application',
      ['https://your-app.com/callback'],
      'mcp:your-app.com:github-tools email'
    )
    
    puts "Client registered successfully!"
    puts "Client ID: #{registration[:client_id]}"
    puts "Expires at: #{Time.at(registration[:expires_at])}"
    puts
    
  rescue => e
    puts "Client registration failed: #{e.message}"
    return
  end
  
  puts "Step 2: Initialize OAuth Flow"
  
  # Initialize OAuth client with the registered client ID
  client = MCPOAuthClient.new(
    registration[:client_id],
    'https://auth.mcp.r167.dev',
    'https://your-app.com/callback',
    'mcp:your-app.com:github-tools email'
  )
  
  # Generate PKCE challenge
  pkce = client.generate_pkce
  puts "Generated PKCE challenge: #{pkce[:code_challenge]}"
  
  # Generate random state for CSRF protection
  state = Base64.urlsafe_encode64(SecureRandom.random_bytes(16), padding: false)
  
  # Get authorization URL
  auth_url = client.authorization_url(state, pkce)
  puts "Visit this URL to authorize:"
  puts auth_url
  puts
  
  # After user authorizes and returns with code...
  puts "After authorization, exchange code for tokens:"
  puts "tokens = client.exchange_code_for_tokens(authorization_code, pkce)"
  puts
  
  # Example token refresh
  puts "To refresh tokens:"
  puts "new_tokens = client.refresh_tokens(refresh_token)"
  puts
end

# Example usage for MCP resource server
def example_resource_server
  puts "=== MCP Resource Server Example ==="
  
  # Initialize token validator
  validator = MCPTokenValidator.new(
    'https://auth.mcp.r167.dev/.well-known/jwks.json',
    'https://auth.mcp.r167.dev',
    'mcp:your-app.com:github-tools'
  )
  
  puts "Token validator initialized"
  puts "To validate a token in your API:"
  puts
  puts <<~RUBY
    def authenticate_request(authorization_header)
      return nil unless authorization_header&.start_with?('Bearer ')
      
      token = authorization_header.sub('Bearer ', '')
      
      begin
        claims = validator.validate_token(token)
        puts "Authenticated user: \#{claims[:user_id]} (\#{claims[:email]})"
        puts "Scope: \#{claims[:scope]}"
        claims
      rescue => e
        puts "Authentication failed: \#{e.message}"
        nil
      end
    end
  RUBY
  puts
end

# Example with token manager
def example_token_manager
  puts "=== Token Manager Example ==="
  
  client = MCPOAuthClient.new(
    'your-client-id',
    'https://auth.mcp.r167.dev',
    'https://your-app.com/callback',
    'mcp:your-app.com:github-tools email'
  )
  
  token_manager = MCPTokenManager.new(client)
  
  puts "Token manager handles automatic refresh:"
  puts "access_token = token_manager.get_access_token"
  puts "# Automatically refreshes if token is expired/expiring"
  puts
end

# HTTP client wrapper with automatic token management
class MCPAPIClient
  def initialize(oauth_client, api_base_url)
    @token_manager = MCPTokenManager.new(oauth_client)
    @api_base_url = api_base_url
    @http_timeout = 30
  end

  # Make authenticated API request
  def get(path, headers = {})
    make_request(:get, path, nil, headers)
  end

  def post(path, body = nil, headers = {})
    make_request(:post, path, body, headers)
  end

  # Store tokens after OAuth flow
  def authenticate_with_tokens(tokens)
    @token_manager.store_tokens(tokens)
  end

  private

  def make_request(method, path, body, headers)
    access_token = @token_manager.get_access_token
    raise "No valid access token available" unless access_token

    uri = URI("#{@api_base_url}#{path}")
    
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = uri.scheme == 'https'
    http.read_timeout = @http_timeout
    
    request = case method
              when :get
                Net::HTTP::Get.new(uri)
              when :post
                Net::HTTP::Post.new(uri)
              else
                raise "Unsupported HTTP method: #{method}"
              end
    
    # Set authorization header
    request['Authorization'] = "Bearer #{access_token}"
    
    # Set other headers
    headers.each { |k, v| request[k] = v }
    
    # Set body for POST requests
    if body && method == :post
      request['Content-Type'] = 'application/json' unless headers['Content-Type']
      request.body = body.is_a?(String) ? body : body.to_json
    end
    
    response = http.request(request)
    
    case response
    when Net::HTTPSuccess
      response
    when Net::HTTPUnauthorized
      # Clear tokens and re-raise
      @token_manager.clear_tokens
      raise "Authentication failed: #{response.body}"
    else
      raise "API request failed: #{response.code} #{response.body}"
    end
  end
end

# Main execution
if __FILE__ == $PROGRAM_NAME
  puts "MCP OAuth Client Examples for Ruby"
  puts "===================================="
  puts
  
  example_oauth_client
  example_resource_server
  example_token_manager
  
  puts "=== Complete API Client Example ==="
  puts "See MCPAPIClient class for a complete HTTP client with automatic token management"
  puts
end