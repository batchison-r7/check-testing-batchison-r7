require 'sinatra'
require 'octokit'
require 'dotenv/load' # Manages environment variables
require 'json'
require 'openssl'     # Verifies the webhook signature
require 'jwt'         # Authenticates a GitHub App
require 'time'        # Gets ISO 8601 representation of a Time object
require 'logger'      # Logs debug statements
require 'git'

set :port, 3000
set :bind, '0.0.0.0'

SIA_FORM = <<~EOF
  Please provide a Security Impact Analysis.

  https://docs.google.com/spreadsheets/d/18qCKxDyzqi6gvYV-HQBl8GChx2BUUiCZqnLxIW1dm-M
EOF

class GHAapp < Sinatra::Application
  # Expects that the private key in PEM format. Converts the newlines
  PRIVATE_KEY = OpenSSL::PKey::RSA.new(ENV['GITHUB_PRIVATE_KEY'].gsub('\n', "\n"))

  # Secret is used to verify that webhooks are sent by GitHub.
  WEBHOOK_SECRET = ENV['GITHUB_WEBHOOK_SECRET']

  # The GitHub App's identifier (type integer) set when registering an app.
  APP_IDENTIFIER = ENV['GITHUB_APP_IDENTIFIER']

  # Turn on Sinatra's verbose logging during development
  configure :development do
    set :logging, Logger::DEBUG
  end

  # Before each request to the `/event_handler` route
  before '/event_handler' do
    get_payload_request(request)
    verify_webhook_signature
    authenticate_app
    authenticate_installation(@payload)
  end

  post '/event_handler' do
    # Event type from HTTP_X_GITHUB_EVENT header
    case request.env['HTTP_X_GITHUB_EVENT']
    when 'check_suite'
      create_check_run if @payload['action'] == 'requested' || @payload['action'] == 'rerequested'
    when 'check_run'
      if @payload['check_run']['app']['id'].to_s === APP_IDENTIFIER # Event is sent to this app
        case @payload['action']
        when 'created'
          initiate_check_run
        when 'rerequested'
          create_check_run
        when 'requested_action'
          take_requested_action
        end
      end
    end
    200 # success status
  end

  helpers do
    # Create a new check run with status "queued"
    def create_check_run
      @installation_client.create_check_run(
        @payload['repository']['full_name'],    # GitHub repository
        'Significant Change',                   # Name of the check run.
        @payload['check_run'].nil? ? @payload['check_suite']['head_sha'] : @payload['check_run']['head_sha'], # Commit SHA
        accept: 'application/vnd.github+json' # Avoid API not production ready warning
      )
    end

    # Start the CI process
    def initiate_check_run
      @installation_client.update_check_run(
        @payload['repository']['full_name'],
        @payload['check_run']['id'],
        status: 'in_progress',
        accept: 'application/vnd.github+json'
      )

      # Updated check run summary and text parameters
      summary = 'Is this a significant change?'
      text = 'Learn more at: https://wiki.corp.rapid7.com/display/PD/Fedramp+Significant+Change+Management'
      conclusion = 'failure'

      # Mark the check run as complete
      @installation_client.update_check_run(
        @payload['repository']['full_name'],
        @payload['check_run']['id'],
        status: 'completed',
        conclusion: conclusion,
        output: {
          title: 'Significant Change',
          summary: summary,
          text: text
        },
        actions: [
          {
            label: 'Yes',
            description: 'This is a significant change.',
            identifier: 'is_sig_change'
          },
          {
            label: 'No',
            description: 'This is NOT a significant change.',
            identifier: 'not_sig_change'
          }
        ],
        accept: 'application/vnd.github+json'
      )
    end

    # Handles the check run `requested_action` events
    def take_requested_action
      case @payload['requested_action']['identifier']
      when 'not_sig_change'
        # Mark the check run as complete!
        @installation_client.update_check_run(
          @payload['repository']['full_name'],
          @payload['check_run']['id'],
          status: 'completed',
          conclusion: 'success',
          accept: 'application/vnd.github+json'
        )
      when 'is_sig_change'
        @installation_client.update_check_run(
          @payload['repository']['full_name'],
          @payload['check_run']['id'],
          status: 'completed',
          conclusion: 'failure',
          output: {
            title: 'Security Impact Analysis Required',
            summary: SIA_FORM,
            # summary: 'Please provide a security impact analysis.',
            text: 'Sample SIA here: https://docs.google.com/spreadsheets/d/18qCKxDyzqi6gvYV-HQBl8GChx2BUUiCZqnLxIW1dm-M'
          },
          actions: [{
            label: 'SIA Complete',
            description: 'Successfully submitted.',
            identifier: 'not_sig_change'
          }],
          accept: 'application/vnd.github+json'
        )
      end
    end

    # Saves the raw payload and converts the payload to JSON format
    def get_payload_request(request)
      request.body.rewind
      @payload_raw = request.body.read
      begin
        @payload = JSON.parse @payload_raw
      rescue StandardError => e
        raise 'Invalid JSON (#{e}): #{@payload_raw}'
      end
    end

    # Instantiate an Octokit client authenticated as a GitHub App.
    def authenticate_app
      payload = {
        iat: Time.now.to_i, # The time that this JWT was issued, _i.e._ now.
        exp: Time.now.to_i + (10 * 60),   # JWT expiration time (10 minute maximum)
        iss: APP_IDENTIFIER               # Your GitHub App's identifier number
      }
      jwt = JWT.encode(payload, PRIVATE_KEY, 'RS256')         # Cryptographically sign the JWT.
      @app_client ||= Octokit::Client.new(bearer_token: jwt)  # Create the Octokit client, using the JWT as the auth token.
    end

    # Instantiate an Octokit client to run API operations.
    def authenticate_installation(payload)
      @installation_id = payload['installation']['id']
      @installation_token = @app_client.create_app_installation_access_token(@installation_id)[:token]
      @installation_client = Octokit::Client.new(bearer_token: @installation_token)
    end

    def verify_webhook_signature
      their_signature_header = request.env['HTTP_X_HUB_SIGNATURE'] || 'sha1='
      method, their_digest = their_signature_header.split('=')
      our_digest = OpenSSL::HMAC.hexdigest(method, WEBHOOK_SECRET, @payload_raw)
      halt 401 unless their_digest == our_digest

      # The X-GITHUB-EVENT header provides the name of the event.
      # The action value indicates the which action triggered the event.
      logger.debug "---- received event #{request.env['HTTP_X_GITHUB_EVENT']}"
      logger.debug "----    action #{@payload['action']}" unless @payload['action'].nil?
    end
  end

  run! if __FILE__ == $0
end
