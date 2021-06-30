class ApplicationController < ActionController::API
  include ActionController::HttpAuthentication::Token::ControllerMethods
  # for using system Token like Authorization: system <server_token>
  # overwrite https://github.com/rails/rails/blob/83217025a171593547d1268651b446d3533e2019/actionpack/lib/action_controller/metal/http_authentication.rb#L409
  ActionController::HttpAuthentication::Token.const_set("TOKEN_REGEX", /^(Token|Bearer|System|token|bearer|system)\s+/)
  before_action :authenticate

  private
    def authenticate
      authenticate_or_request_with_http_token do |token, options|
        # Compare the tokens in a time-constant manner, to mitigate
        # timing attacks.
        ActiveSupport::SecurityUtils.secure_compare(token, Rails.application.credentials.system[:token])
      end
    end
end
