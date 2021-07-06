class ApplicationController < ActionController::API
  silence_warnings do
    # for using system Token like Authorization: system <server_token>
    # overwrite https://github.com/rails/rails/blob/83217025a171593547d1268651b446d3533e2019/actionpack/lib/action_controller/metal/http_authentication.rb#L409
    ActionController::HttpAuthentication::Token.const_set("TOKEN_REGEX", /^(Token|Bearer|System|token|bearer|system)\s+/)
  end
  include ActionController::HttpAuthentication::Token::ControllerMethods
  before_action :authenticate

  # overwrite all exception to be sure we catch it
  rescue_from Exception, :with => :error_generic

  rescue_from Faraday::BadRequestError, :with => :error_cwa_server
  rescue_from ArgumentError, :with => :error_generic
  rescue_from RuntimeError, :with => :error_generic
  rescue_from NoMethodError, :with => :error_generic

  private
    def authenticate
      authenticate_or_request_with_http_token do |token, options|
        # Compare the tokens in a time-constant manner, to mitigate
        # timing attacks.
        ActiveSupport::SecurityUtils.secure_compare(token, ENV["SERVER_TOKEN"]) # /*Rails.application.credentials.system[:token]*/
      end
    end
    def error_generic(error)
      logger.error error
      render json: { errors: [error.to_s] }, status: error.respond_to?(:status) ? error.status : 500
    end
    def error_cwa_server(error)
      logger.error error
      render json: { errors: [error.response[:body]] }, status: error.response[:status]
    end
end
