class DccController < ApplicationController
  def initialize
    # public keys for existing test results
    @pub_keys = {}

    # constants variables for DCC JSON data
    $issuer = "Robert Koch Institute"
    $version = "1.3.0"
    $issuer_country = "DE"
    $disease = "840539006"
    $test_type = "LP217198-3"
    $expiration_dates = 2
  end
  # POST /dcc
  def create
    #1. JSON / Test Registration / Assembled by Partner SW – QR(base64url) to CWA
    dcc = generate_cwa_link dcc_params
    
    #2. JSON / Test Result / Assembled by Partner SW – POST to DCC-Service 
    logger.info "build dccs object for cwa-server..."
    dccs = {
      testResults: [{
         id: dcc[:cwa_test_id],
         result: dcc[:result]
     }],
     labId: dcc[:labId]
    }
    logger.info dccs
    cwa_server_response = CWA_request dccs
    logger.info "quicktest results response: #{cwa_server_response.body}"

    #3 JSON / DDC-Info from Backend for each recieved Test / Assembled by DCC-Service – GET on [Base-URL des DCC-Servers]/version/v1/publicKey/search/{labId}
    get_pub_keys dcc          # Periodic function 10s
    
    #4 JSON / DCC-“Kernel“ / Assembled by Partner SW based on exchanged information
    dcc_data = build_DCC_data dcc
    logger.info "DCC JSON object:#{dcc_data}"

    #5 DCC data structure(HCERT container)
    cbor_hcert = build_CBOR_HCERT dcc, dcc_data
    logger.info "HCERT container:#{cbor_hcert}"

    # build COSE structure for DCC hash calculation
    dcc_hash_hex = build_COSE_structure cbor_hcert
    dcc_hash_hex = Base64.encode64(dcc_hash_hex)
    logger.info "dccHashHex:#{dcc_hash_hex}"

    # generate 32byte key for AES encryption
    key_32_bytes = generate_32_bytes_key
    logger.info "AES key:#{key_32_bytes}"

    # Encryption of the CBOR from the DCC payload using AES256 (AES / CBC / PKCS5Padding; IV = {0, ..., 0}) -> encryptedDcc
    encrypted_DCC = encrypt_DCC_CBOR cbor_hcert, key_32_bytes
    logger.info "encrypted DCC:#{encrypted_DCC}"
    encrypted_DCC = Base64.encode64(encrypted_DCC)
    logger.info "encrypted DCC:#{encrypted_DCC}"

    # Encrypt 32 byte key using public key from step "Determination of public keys for existing test results"
    data_Encryption_Key = encrypt_32_key key_32_bytes
    data_Encryption_Key = Base64.encode64(data_Encryption_Key)
    logger.info "dataEncryptionKey:#{data_Encryption_Key}"

    # Send DCC Data to Proxy
    partial_DCC = send_DCC_data dcc_hash_hex, encrypted_DCC, data_Encryption_Key
    logger.info "partialDCC:#{partial_DCC}"
    
    # cwa server returns 204 - no content if it succeeds, as we want to return the data we transform it to 200 - OK
    render json: partial_DCC, status: cwa_server_response.success? ? :ok : cwa_server_response.status
  end

  private

  def dcc_params
    dcc = params[:dcc]
    logger.info "check dcc params...#{dcc}"
    # check & validate params
    # TODO: do we get timestamp in correct format, or should we transform it to "Unix Epoch Timestamp Format (Sekunden)"
    params.require([:timestamp,:result])

    # result must be between 5=pending, 6=negative, 7=positive, 8=test invalid
    unless params[:result] >= 5 && params[:result] <= 8
      raise ArgumentError.new("testresult for the given test must be between: 5=pending, 6=negative, 7=positive, 8=test invalid")
    end
    if (params.has_key?(:fn) && params.has_key?(:ln) && params.has_key?(:dob) && params.has_key?(:testid))
      dcc[:anonymous] = false
      logger.info "parse given birthdate..."
      dcc[:dob] = Date.parse(dcc[:dob]).strftime("%Y-%m-%d")
    else
      dcc[:anonymous] = true
    end
    # take timestamp as utc timestamp or string representation
    logger.info "parse given test-timestamp...#{params}"
    dcc[:timestamp] = dcc[:timestamp].is_a?(String) ? Time.parse(dcc[:timestamp]).to_i : Time.at(dcc[:timestamp]).to_i
    dcc[:labId] = "covidGo#{DateTime.now.strftime('%Q').to_s}"
    dcc
  end

  # cwa_test_id also named SHA256-Hash or hash
  # SHA256-Hash: [dob]#[fn]#[ln]#[timestamp]#[testid]#[salt]
  def cwa_test_id dcc
    hash_value =
      if dcc[:anonymous]
        "#{dcc[:timestamp]}##{dcc[:salt]}"
      else
        "#{dcc[:dob]}##{dcc[:fn]}##{dcc[:ln]}##{dcc[:timestamp]}##{dcc[:testid]}##{dcc[:salt]}"
      end

    Digest::SHA256.hexdigest hash_value
  end

  # TODO: refactor this !!
  def build_json dcc
    if dcc[:anonymous]
      '{ "timestamp": ' +dcc[:timestamp].to_s+', "salt": "' +dcc[:salt]+'", "hash": "' +dcc[:cwa_test_id]+'" }'
    else
      '{ "fn": "' + dcc[:fn]+'", "ln": "' +dcc[:ln]+'", "dob": "' +dcc[:dob]+'", "timestamp": ' +dcc[:timestamp].to_s+', "testid": "' +dcc[:testid]+'", "salt": "' +dcc[:salt]+'", "hash": "' +dcc[:cwa_test_id]+'" }'
    end
  end

  def CWA_request dccs
    #"https://quicktest-result-cff4f7147260.coronawarn.app/"
    # cwa_url = Rails.env.production? ? "https://quicktest-result.coronawarn.app/" : "https://quicktest-result-dfe4f5c711db.coronawarn.app/"
    cwa_url = ENV["CWA_URL"]
    logger.info "push to cwa server #{cwa_url}..."

    client_key = OpenSSL::PKey::RSA.new(File.read(ENV["KEY_PATH"]), ENV["KEY_PASSWORD"])
    client_cert = OpenSSL::X509::Certificate.new(File.read(ENV["CERT_PATH"]))
    cwa_server_connection = Faraday.new cwa_url,
      ssl: {
        client_key: client_key,
        client_cert: client_cert
      } do |c|
        c.use Faraday::Response::RaiseError
      end
      logger.info dccs
    cwa_server_response = cwa_server_connection.post("api/v1/quicktest/results") do |request|
      request.headers['Content-Type'] = 'application/json'
      request.body = dccs.to_json
      logger.info "quicktest result request Headers:#{request}"
    end

    cwa_server_response
  end

  def generate_cwa_link dcc, salt=SecureRandom.hex(16)
    # generate 128-bit salt
    logger.info "create secure salt..."
    dcc[:salt] = salt
    # build the hash (SHA256-Hash)
    logger.info "create CWA SHA256 hash..."
    dcc[:cwa_test_id] = cwa_test_id dcc
    # build json object (be carefull regarding spaces, see https://github.com/corona-warn-app/cwa-quicktest-onboarding/issues/11)
    logger.info "build cwa json object..."
    cwa_json = build_json dcc
    logger.info cwa_json
    # generate base64 encoded object for building the qr_code
    logger.info "generate base64 encoded cwa object..."
    dcc[:cwa_base64_object] = Base64.urlsafe_encode64(cwa_json)
    logger.info dcc[:cwa_base64_object]

    # TODO: we need probably to remove the "==" at the end of string
    dcc[:cwa_link] = "https://s.coronawarn.app?v=1##{dcc[:cwa_base64_object]}"

    dcc
  end

  def get_pub_keys dcc, delay=10
    # to determin public keys for existing test results(periodic function)
    Thread.new do
      loop do
        dcc_url = ENV["DCC_URL"]      # DCC server address
        logger.info "Determination of public keys from dcc server #{dcc_url}..."

        client_key = OpenSSL::PKey::RSA.new(File.read(ENV["KEY_PATH"]), ENV["KEY_PASSWORD"])
        client_cert = OpenSSL::X509::Certificate.new(File.read(ENV["CERT_PATH"]))
        dcc_server_connection = Faraday.new dcc_url,
          ssl: {
            client_key: client_key,
            client_cert: client_cert
          } do |c|
            c.use Faraday::Response::RaiseError
          end

        pub_keys_response = dcc_server_connection.get("version/v1/publicKey/search/#{dcc[:labId]}")
        logger.info "public keys for current labId response: #{pub_keys_response.body}"

        data = JSON.parse(pub_keys_response.body)
        testId = Digest::SHA256.hexdigest dcc[:cwa_test_id]

        data.each do |key|
          if(testId == key[:testId])
            @pub_keys = key
          end
        end

        logger.info "the public key for current test id: #{@pub_keys}"
        sleep delay
      end
    end
  end

  def build_DCC_data dcc
    # build JSON data schema
    data = {}
    test_data = []

    @pub_keys.each do |item|
      test_data.push({
        ci: item[:dcci],
        co: $issuer_country,
        is: $issuer,
        tg: $disease,
        tt: $test_type,
        sc: Time.at(dcc[:timestamp]),
        tr: 260415000,          # temporary data
        tc: "FTA TestZentrum",    # temporary data
        ma: 1468    # temporary data
      })
    end

    data[:t] = test_data
    data = data.merge({
      dob: dcc[:dob],
      nam: {
        fn: dcc[:ln],
        fnt: convert_string_ICAO(dcc[:ln].force_encoding('iso-8859-1').encode('utf-8').upcase),
        gn: dcc[:fn],
        gnt: convert_string_ICAO(dcc[:fn].force_encoding('iso-8859-1').encode('utf-8').upcase)
      },
      ver: $version
    })
    
    data
  end

  def build_CBOR_HCERT dcc, dcc_data
    # build HCERT container data with JSON schema
    data = {
      1 => "DE",
      4 => dcc[:timestamp],
      6 => dcc[:timestamp] + $expiration_dates*60*60*24,
      -260 => {
        1 => dcc_data
      }
    }
    logger.info "before conversion to CBOR object data:#{data}"

    encoded_data = data.to_cbor    # to convert CBOR data format
    logger.info encoded_data
    byte_arr = encoded_data.unpack("C*")
    logger.info byte_arr
    cbor_hcert = byte_arr.map{ |byte| byte.to_s(16).force_encoding('iso-8859-1').encode('utf-8').upcase.length == 1 ? "0#{byte.to_s(16).force_encoding('iso-8859-1').encode('utf-8').upcase}":byte.to_s(16).force_encoding('iso-8859-1').encode('utf-8').upcase}.join("")
    logger.info "CBOR:#{cbor_hcert}"

    cbor_hcert
  end

  # Assemble COSE structure for dccHash calculation only   

  # Creates CBOR for the signing object for the dccHash calculation only 
  # Since the CBOR prefix coding is always the same, just add the CBOR of the HCERT
  # Attention: This just an example - has to be adapted if CBOR HEX > 255 Byte (0xFF)!
  def build_COSE_structure cbor_hcert
    cbor_length = (cbor_hcert.length / 2).to_s(16)
    logger.info "CBOR data length:#{cbor_length}"
    cbor_cose = ""
    case cbor_length.length
    when 1
      cbor_cose = "846A5369676E61747572653143A1012640580#{cbor_length}#{cbor_hcert}"
    when 2
      cbor_cose = "846A5369676E61747572653143A101264058#{cbor_length}#{cbor_hcert}"
    when 3
      cbor_cose = "846A5369676E61747572653143A1012640590#{cbor_length}#{cbor_hcert}"
    when 4
      cbor_cose = "846A5369676E61747572653143A101264059#{cbor_length}#{cbor_hcert}"
    else
      cbor_cose = "Unexpeted Error EXITING - CBOR TOO LONG"
    end

    logger.info "CBOR for Hash: #{cbor_cose}"

    logger.info hex_to_bin(cbor_cose)
    dccHashHex = OpenSSL::Digest.digest("SHA256", hex_to_bin(cbor_cose))

    dccHashHex
  end

  def generate_32_bytes_key
    # generate a 32 Byte Key
    bin_to_hex(Random.new.bytes(32))
  end
  
  def encrypt_DCC_CBOR cbor_hcert, key_32_bytes
    # encypt CBOR of HCERT 
    iv = "0"*32
    # encrypt DCC with AES256 (CBC/PKSC5Padding)
    aes = OpenSSL::Cipher.new('AES-256-CBC')
    aes.encrypt
    aes.key = hex_to_bin(key_32_bytes)
    aes.iv = hex_to_bin(iv)
    aes.update(hex_to_bin(cbor_hcert)) + aes.final

    # encryptedDcc
  end

  def encrypt_32_key key_32_bytes 
    # encrypt DEK with Public Key
    private_key = @pub_keys[:publicKey]?Base64.decode64(@pub_keys[:publicKey]):1024
    # private_key = private_key?private_key:1024
    # private_key = 'MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAobtfXfsyQOKpeG0derCkCs/3FJjWJJ+DxseXTiFuhGaOCPaqblyclmtiZ+WmN0Ix5O7eEJrKlh43cD3qN8AUGNIQ8W1LAFdu5j3nVpk6g5Call/JPGvF1jBhew7pt8oHZBr6MtNi0L3FG3QRhHFF2IMZaF3pqK4JOf5XSzOdL+OQXiIRqsP0Mm6bC0MuzHSwwYu1+N29yDI7CyazbXtgvmPgSN3yCvvhHu71aXzTRJvj3sHBusOQHssQnd+VY4Q9QqTsJcKOegrxo7i9oePTHDNG895VH4TpSBHn5Q50wDt3ElCnfWbsoO2utlOXWLEUrE0PlX2uqMVu9MJsYtNqcVSWvo9iWF9JssGkOLV8SY0a+h9WWQHtx9+6BdiGRAjwvby7rH4Fouv9aUOQd72sEur5wu5h0ngBHb4oGGlDPFBEm+J877Ol/jvER8Eohq0sRqpqxsFVgmLc0Dwf6qVHRMXkyMFS30A5CJfdJrzXvYab1cGgV/fCkuPrJ78Wi59nAgMBAAE='
    key = OpenSSL::PKey::RSA.new(private_key)
    label = ''
    md_oaep = OpenSSL::Digest::SHA256
    md_mgf1 = OpenSSL::Digest::SHA256
    data_Encryption_Key = key.public_encrypt_oaep(hex_to_bin(key_32_bytes), label, md_oaep, md_mgf1)
    logger.info "data_Encryption_Key:#{data_Encryption_Key}"

    data_Encryption_Key
  end

  def send_DCC_data dcc_hash_hex, encrypted_DCC, data_Encryption_Key
    testId = @pub_keys[:testId]
    # testId = "986adbf41719f9eb5615fa5216b4640a7bff7860cd73f9ed4586eaef53173ad2"
    dcc_json = {
      dccHash: dcc_hash_hex,
      encryptedDcc: encrypted_DCC,
      dataEncryptionKey: data_Encryption_Key
    }
    logger.info "dcc_json hash:#{dcc_json}"
    dcc_json = dcc_json.to_json
    logger.info "dcc_json json:#{dcc_json}"

    dcc_url = ENV["DCC_URL"]
    logger.info "push to dcc server #{dcc_url}..."

    client_key = OpenSSL::PKey::RSA.new(File.read(ENV["KEY_PATH"]), ENV["KEY_PASSWORD"])
    client_cert = OpenSSL::X509::Certificate.new(File.read(ENV["CERT_PATH"]))
    dcc_server_connection = Faraday.new dcc_url,
      ssl: {
        client_key: client_key,
        client_cert: client_cert
      } do |c|
        c.use Faraday::Response::RaiseError
      end
      logger.info dcc_json
    dcc_server_response = dcc_server_connection.post("version/v1/test/#{testId}/dcc") do |request|
      request.headers['Content-Type'] = 'application/json'
      request.body = dcc_json
      logger.info "request:#{request}"
    end

    dcc_server_response
  end

  def bin_to_hex(s)     #strToHex equal to bin2hex in PHP
    s.unpack('H*').first
  end
  
  def hex_to_bin(s)     # hexToStr
    s.scan(/../).map { |x| x.hex }.pack('c*')
  end

=begin
* Replaces special characters in a string with their "non-special" counterpart.
* The function is an example only and not completely tested, please perform further tests and 
* changes to meet the requirements of VIZ to MRT conversion
*
* See See 9303_p3 Section 6 - A, B and C (04.08.2021) ICAO Eighth Edition 2021
* Conversion of arabic Numbers to Roman numbers from 1-9 only
* fn or ln should NOT contain arabic numbers! - See Definition of VIZ - anyhow, some Numbers are mapped below.
* Known problems: arabic (Section C) without shadda (double) and teh marbuta (end) handling ... 
*
* @param string
* @return string
=end
def convert_string_ICAO string
   table = {
    '1'=>'I',
    '2'=>'II',
    '3'=>'III',
    '4'=>'IV',
    '5'=>'V',
    '6'=>'VI',
    '7'=>'VII',
    '8'=>'VIII',
    '9'=>'IX',
    ' '=>'<',
    '-'=>'<',
    '\''=>'',
    ','=>'',
    ':'=>'',
    ';'=>'',
    '.'=>'',
    'À'=>'A',
    'Á'=>'A',
    'Â'=>'A',
    'Ã'=>'A',
    'Ä'=>'AE',
    'Å'=>'AA',
    'Æ'=>'AE',
    'Ç'=>'C',
    'È'=>'E',
    'É'=>'E',
    'Ê'=>'E',
    'Ë'=>'E',
    'Ì'=>'I',
    'Í'=>'I',
    'Î'=>'I',
    'Ï'=>'I',
    'Ð'=>'D',
    'Ñ'=>'N',
    'Ò'=>'O',
    'Ó'=>'O',
    'Ô'=>'O',
    'Õ'=>'O',
    'Ö'=>'OE',
    'Ø'=>'OE',
    'Ù'=>'U',
    'Ú'=>'U',
    'Û'=>'U',
    'Ü'=>'UE',
    'Ý'=>'Y',
    'Þ'=>'TH',
    'Ā'=>'A',
    'Ă'=>'A',
    'Ą'=>'A',
    'Ć'=>'C',
    'Ĉ'=>'C',
    'Ċ'=>'C',
    'Č'=>'C',
    'Ď'=>'D',
    'Ð'=>'D',
    'Ē'=>'E',
    'Ĕ'=>'E',
    'Ė'=>'E',
    'Ę'=>'E',
    'Ě'=>'E',
    'Ĝ'=>'G',
    'Ğ'=>'G',
    'Ġ'=>'G',
    'Ģ'=>'G',
    'Ĥ'=>'H',
    'Ħ'=>'H',
    'Ĩ'=>'I',
    'Ī'=>'I',
    'Ĭ'=>'I',
    'Į'=>'I',
    'İ'=>'I',
    'I'=>'I',
    'Ĳ'=>'IJ',
    'Ĵ'=>'J',
    'Ķ'=>'K',
    'Ĺ'=>'L',
    'Ļ'=>'L',
    'Ľ'=>'L',
    'Ŀ'=>'L',
    'Ł'=>'L',
    'Ń'=>'N',
    'Ņ'=>'N',
    'Ň'=>'N',
    'Ŋ'=>'N',
    'Ō'=>'O',
    'Ŏ'=>'O',
    'Ő'=>'O',
    'Œ'=>'OE',
    'Ŕ'=>'R',
    'Ŗ'=>'R',
    'Ř'=>'R',
    'Ś'=>'S',
    'Ŝ'=>'S',
    'Ş'=>'S',
    'Š'=>'S',
    'Ţ'=>'T',
    'Ť'=>'T',
    'Ŧ'=>'T',
    'Ũ'=>'U',
    'Ū'=>'U',
    'Ŭ'=>'U',
    'Ů'=>'U',
    'Ű'=>'U',
    'Ų'=>'U',
    'Ŵ'=>'W',
    'Ŷ'=>'Y',
    'Ÿ'=>'Y',
    'Ź'=>'Z',
    'Ż'=>'Z',
    'Ž'=>'Z',
    'ẞ'=>'SS',
    'Ё'=>'E',
    'Ћ'=>'D',
    'Є'=>'IE',
    'Ѕ'=>'DZ',
    'І'=>'I ',
    'Ї'=>'I',
    'Ј'=>'J',
    'Љ'=>'LJ',
    'Њ'=>'NJ',
    'Ќ'=>'K',
    'ў'=>'U',
    'Џ'=>'DZ',
    'А'=>'A',
    'Б'=>'B',
    'В'=>'V',
    'Г'=>'G',
    'Д'=>'D',
    'Е'=>'E',
    'Ж'=>'ZH',
    'З'=>'Z',
    'И'=>'I',
    'Й'=>'I',
    'К'=>'K',
    'Л'=>'L',
    'М'=>'M',
    'Н'=>'N',
    'О'=>'O',
    'П'=>'P',
    'Р'=>'R',
    'С'=>'S',
    'Т'=>'T',
    'У'=>'U',
    'Ф'=>'F',
    'ء'=>'XE',
    'آ'=>'XAA',
    'أ'=>'XAE',
    'ؤ'=>'U',
    'إ'=>'I',
    'ئ'=>'XI',
    'ا'=>'A',
    'ب'=>'B',
    'ة'=>'XTA',
    'ت'=>'T',
    'ث'=>'XTH',
    'ج'=>'J',
    'ح'=>'XH',
    'خ'=>'XKH',
    'د'=>'D',
    'ذ'=>'XDH',
    'ر'=>'R',
    'ز'=>'Z',
    'س'=>'S',
    'ش'=>'XSH',
    'ص'=>'XSS',
    'ض'=>'XDZ',
    'ط'=>'XTT',
    'ظ'=>'XZZ',
    'ع'=>'E',
    'غ'=>'G',
    'ف'=>'F',
    'ق'=>'Q',
    'ك'=>'K',
    'ل'=>'L',
    'م'=>'M',
    'ن'=>'N',
    'ه'=>'H',
    'و'=>'W',
    'ى'=>'XAY',
    'ي'=>'Y',
    'ٱ'=>'XXA',
    'ٹ'=>'XXT',
    'ټ'=>'XRT',
    'پ'=>'P',
    'ځ'=>'XKE',
    'څ'=>'XXH',
    'چ'=>'XC',
    'ڈ'=>'XXD',
    'ډ'=>'XDR',
    'ڑ'=>'XXR',
    'ړ'=>'XRR',
    'ږ'=>'XRX',
    'ژ'=>'XJ',
    'ښ'=>'XXS',
    'ک'=>'XKK',
    'ګ'=>'XXK',
    'ڭ'=>'XNG',
    'گ'=>'XGG',
    'ں'=>'XNN',
    'ڼ'=>'XXN',
    'ه'=>'XDO',
    'ۀ'=>'XYH',
    'ہ'=>'XXG',
    'ۂ'=>'XGE',
    'ۃ'=>'XTG',
    'ى'=>'XYA',
    'ۍ'=>'XXY',
    'ې'=>'Y',
    'ے'=>'XYB',
    'ۓ'=>'XBE'
  }
  table.each do |key, value|
    string = string.gsub(key, value)
  end
  #  Currency symbols: £¤¥€  - we dont bother with them for now
   string = string.gsub(/[^\x9\xA\xD\x20-\x7F]/u, "");

   string;
   end
end