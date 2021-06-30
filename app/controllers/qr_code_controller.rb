class QrCodeController < ApplicationController
  def qr_code_params
    # TODO: do we get timestamp in correct format, or should we transform it to "Unix Epoch Timestamp Format (Sekunden)"
    params.require([:fn,:ln,:dob,:timestamp])
    params.require(:qr_code).permit(:fn,:ln,:dob,:timestamp, :testid)
  end

  # cwa_test_id also named SHA256-Hash or hash
  # SHA256-Hash: [dob]#[fn]#[ln]#[timestamp]#[testid]#[salt]
  def cwa_test_id qr_code, salt
    hash_value = "#{qr_code.dob.strftime("%Y-%m-%d")}##{qr_code.fn}##{qr_code.ln}##{qr_code.timestamp.to_i}##{qr_code.testid}##{salt}"
    Digest::SHA256.hexdigest hash_value
  end

  # TODO: refactor this !!
  def build_json qr_code, salt
    '{ "fn": "' + qr_code.fn+'", "ln": "' +qr_code.ln+'", "dob": "' +qr_code.dob.strftime("%Y-%m-%d")+'", "timestamp": ' +qr_code.timestamp.to_i.to_s+', "testid": "' +qr_code.testid+'", "salt": "' +salt+'", "hash": "' +qr_code.cwa_test_id+'" }'
  end

  def create
    # new qr_code object with given params
    qr_code = QrCode.new(qr_code_params)
    # if no testid is given we generate a uuid
    qr_code.testid = SecureRandom.uuid unless qr_code.testid.present?
    # take timestamp as utc timestamp or string representation
    qr_code.timestamp = qr_code_params[:timestamp].is_a?(String) ? Time.parse(qr_code_params[:timestamp]) : Time.at(qr_code_params[:timestamp])
    # generate 128-bit salt
    salt = SecureRandom.hex(16) # "759F8FF3554F0E1BBF6EFF8DE298D9E9" # SecureRandom.hex(16)
    # build the hash (SHA256-Hash)
    cwa_test_id = cwa_test_id qr_code, salt
    qr_code.cwa_test_id = cwa_test_id
    # build json object (be carefull regarding spaces, see https://github.com/corona-warn-app/cwa-quicktest-onboarding/issues/11)
    cwa_json = build_json qr_code, salt
    # generate base64 encoded object for building the qr_code
    qr_code.cwa_base64_object = Base64.urlsafe_encode64(cwa_json)
    qr_code.save!

    # TODO: we need probably to remove the "==" at the end of string
    render json:qr_code.as_json.merge(
      { cwa_link: "https://s.coronawarn.app?v=1##{qr_code.cwa_base64_object}" }
    )
  end
end