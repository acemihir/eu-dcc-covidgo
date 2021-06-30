class HealthController < ApplicationController
  def index
    render json: {
      "type": "health",
      # "id": "1624832566-472", # TODO
      "attributes": {
        "name": "cwa-gateway",
        "version": "0.0.1",
        "env": Rails.env,
        "dbStatus": "TODO" # TODO
      }
    }
  end
end