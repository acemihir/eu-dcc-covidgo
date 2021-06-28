class QrCodeController < ApplicationController
  def qr_code_params
    # TODO: do we get timestamp in correct format, or should we transform it to "Unix Epoch Timestamp Format (Sekunden)"
    params.require([:fn,:ln,:dob,:timestamp])
    params.require(:qr_code).permit(:fn,:ln,:dob,:timestamp, :testid) # for using where hash needed
  end

  # cwa_test_id also named SHA256-Hash or hash
  # SHA256-Hash: [dob]#[fn]#[ln]#[timestamp]#[testid]#[salt]
  def cwa_test_id qr_code, salt
    hash_value = "#{qr_code.dob.strftime("%Y-%m-%d")}##{qr_code.fn}##{qr_code.ln}##{qr_code.timestamp}##{qr_code.testid}##{salt}"
    Digest::SHA256.hexdigest hash_value
  end

  def build_json
    # {
    #   "fn": "Erika",
    #   "ln": "Mustermann",
    #   "dob": "1990-12-23",
    #   "timestamp": 1618386548,
    #   "testid": "52cddd8e-ff32-4478-af64-cb867cea1db5",
    #   "salt": "759F8FF3554F0E1BBF6EFF8DE298D9E9",
    #   "hash": "67a50cba5952bf4f6c7eca896c0030516ab2f228f157237712e52d66489d9960"
    # }
  end

  def create
    # new qr_code object with given params
    qr_code = QrCode.new(qr_code_params)
    # generate 128-bit salt
    salt = SecureRandom.hex(16)
    # build the hash (SHA256-Hash)
    cwa_test_id = cwa_test_id qr_code, salt
    qr_code.cwa_test_id = cwa_test_id
    # generate base64 encoded object for building the qr_code
    # TODO: we probably need a correct sorted json object
    qr_code.cwa_base64_object = Base64.encode64(qr_code.to_json.merge({salt: salt}))

    render json:qr_code.to_json
  end
end