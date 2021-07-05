class HealthController < ApplicationController
  skip_before_action :authenticate, only: [:index]

  def index
    render json: {
      "type": "health",
      # "id": "1624832566-472", # TODO
      "attributes": {
        "name": "cwa-gateway",
        "version": "0.0.1",
        "env": Rails.env,
        "dbStatus": "NO-DB (stateless)" # TODO
      }
    }
  end
end