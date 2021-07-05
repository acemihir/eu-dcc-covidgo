class TestResultController < ApplicationController
  def test_result_params
    logger.info "check test_result params...#{params[:test_result]}"
    # check & validate params
    # TODO: do we get timestamp in correct format, or should we transform it to "Unix Epoch Timestamp Format (Sekunden)"
    params.require([:fn,:ln,:dob,:timestamp,:testid,:result])
    # params.require(:test_result).permit(:fn,:ln,:dob,:timestamp,:testid,:result) # for mass assignment

    # result must be between 5=pending, 6=negative, 7=positive, 8=test invalid
    unless params[:result] >= 5 && params[:result] <= 8
      raise ArgumentError.new("testresult for the given test must be between: 5=pending, 6=negative, 7=positive, 8=test invalid")
    end

    test_result = params[:test_result]
    # take timestamp as utc timestamp or string representation
    logger.info "parse given test-timestamp...#{params}"
    test_result[:timestamp] = test_result[:timestamp].is_a?(String) ? Time.parse(test_result[:timestamp]).to_i : Time.at(test_result[:timestamp]).to_i
    logger.info "parse given birthdate..."
    test_result[:dob] = Date.parse(test_result[:dob]).strftime("%Y-%m-%d")

    test_result
  end

  # cwa_test_id also named SHA256-Hash or hash
  # SHA256-Hash: [dob]#[fn]#[ln]#[timestamp]#[testid]#[salt]
  def cwa_test_id test_result
    hash_value = "#{test_result[:dob]}##{test_result[:fn]}##{test_result[:ln]}##{test_result[:timestamp]}##{test_result[:testid]}##{test_result[:salt]}"
    Digest::SHA256.hexdigest hash_value
  end

  # TODO: refactor this !!
  def build_json test_result
    '{ "fn": "' + test_result[:fn]+'", "ln": "' +test_result[:ln]+'", "dob": "' +test_result[:dob]+'", "timestamp": ' +test_result[:timestamp].to_s+', "testid": "' +test_result[:testid]+'", "salt": "' +test_result[:salt]+'", "hash": "' +test_result[:cwa_test_id]+'" }'
  end

  def CWA_request test_results
    #"https://quicktest-result-cff4f7147260.coronawarn.app/"
    # cwa_url = Rails.env.production? ? "https://quicktest-result.coronawarn.app/" : "https://quicktest-result-dfe4f5c711db.coronawarn.app/"
    cwa_url = ENV["CWA_URL"]
    logger.info "push to cwa server #{cwa_url}..."

    client_key = OpenSSL::PKey::RSA.new(File.read('config/credentials/covidgo-wru.key'), ENV["KEY_PASSWORD"])
    client_cert = OpenSSL::X509::Certificate.new(File.read('config/credentials/covidgo-wru.schnelltestportal.de-Server-17f5abbefa6fb59dfa43f1dc8bc4ddfd.cer'))
    cwa_server_connection = Faraday.new cwa_url,
      ssl: {
        client_key: client_key,
        client_cert: client_cert
      } do |c|
        c.use Faraday::Response::RaiseError
      end

    cwa_server_response = cwa_server_connection.post("api/v1/quicktest/results") do |request|
      request.headers['Content-Type'] = 'application/json'
      request.body = test_results.to_json
    end

    cwa_server_response
  end

  # POST /test_result
  def create
    test_result = test_result_params
    # qr_code.testid = SecureRandom.uuid unless qr_code.testid.present? # with statless service we need testid from extern
    # generate 128-bit salt
    logger.info "create secure salt..."
    test_result[:salt] = SecureRandom.hex(16) # "759F8FF3554F0E1BBF6EFF8DE298D9E9" # SecureRandom.hex(16)
    # build the hash (SHA256-Hash)
    logger.info "create CWA SHA256 hash..."
    test_result[:cwa_test_id] = cwa_test_id test_result
    # build json object (be carefull regarding spaces, see https://github.com/corona-warn-app/cwa-quicktest-onboarding/issues/11)
    logger.info "build cwa json object..."
    cwa_json = build_json test_result
    logger.info cwa_json
    # generate base64 encoded object for building the qr_code
    logger.info "generate base64 encoded cwa object..."
    test_result[:cwa_base64_object] = Base64.urlsafe_encode64(cwa_json)
    logger.info test_result[:cwa_base64_object]

    # TODO: we need probably to remove the "==" at the end of string
    test_result[:cwa_link] = "https://s.coronawarn.app?v=1##{test_result[:cwa_base64_object]}"

    logger.info "build test_results object for cwa-server..."
    test_results = {
      testResults: [{
         id: test_result[:cwa_test_id],
         result: test_result[:result]
     }]
    }
    logger.info test_results

    logger.info "push to cwa server..."
    cwa_server_response = CWA_request test_results
    logger.info "response: #{cwa_server_response.body}"

    # cwa server returns 204 - no content if it succeeds, as we want to return the data we transform it to 200 - OK
    render json: test_result.to_json, status: cwa_server_response.success? ? :ok : cwa_server_response.status
  end
end