class TestResultController < ApplicationController
  def test_result_params
    params.require([:testid,:result])
    params.require(:test_result).permit(:testid,:result)
  end

  def CWA_request test_results
    # production: https://quicktest-result.coronawarn.app
    # testing: https://quicktest-result-dfe4f5c711db.coronawarn.app/
    cwa_url = Rails.env.production? ? "https://quicktest-result.coronawarn.app/" : "https://quicktest-result-dfe4f5c711db.coronawarn.app/"

    cwa_server_connection = Faraday.new cwa_url,
      ssl: {
        # client_cert: xx,
        # client_key: xx ,
        # ca_file: xx    ,
        # ca_path: xx    ,
        # cert_store: xx
      }


    cwa_server_response = cwa_server_connection.post("api/v1/quicktest/results") do |request|
      request.headers['Content-Type'] = 'application/json'
      request.body = test_results.to_json
    end

    cwa_server_response

    # cwa_result = RestClient::Request.new(
    #   {
    #     method: :post,
    #     payload: test_results.to_json,
    #     url: "https://quicktest-result-dfe4f5c711db.coronawarn.app/api/v1/quicktest/results",
    #   }
    # ).execute do |response, request, result|
    #     case response.code
    #     when 204
    #       render json: JSON.parse(response.to_str, symbolize_names: true)
    #     when 400
    #       render status: 400, json: { error: "Client Certificate not accepted!" }
    #     else
    #       render status: 400, json: { error: "Invalid response #{response.to_s}" }
    #     end
    #   end
  end

  def create
    # find qr_code / test
    qr_code = QrCode.find_by testid: test_result_params[:testid]
    test_results = {
      testResults: [{
         id: qr_code.cwa_test_id,
         result: test_result_params[:result]
     }]
    }

    cwa_server_response = CWA_request test_results
    render status: cwa_server_response.status, json: {body: cwa_server_response.body}
  end
end