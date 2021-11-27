require_relative "boot"

require "rails"
# Pick the frameworks you want:
require "active_model/railtie"
require "active_job/railtie"
require "active_record/railtie"
require "active_storage/engine"
require "action_controller/railtie"
require "action_mailer/railtie"
require "action_mailbox/engine"
require "action_text/engine"
require "action_view/railtie"
require "action_cable/engine"
# require "sprockets/railtie"
require "rails/test_unit/railtie"
require "cbor"
require "cose"
require "base64"
require "json"
require "faraday"
# Require the gems listed in Gemfile, including any gems
# you've limited to :test, :development, or :production.
Bundler.require(*Rails.groups)

module SrvGwCwa
  class Application < Rails::Application
    # Initialize configuration defaults for originally generated Rails version.
    config.load_defaults 6.1

    # Configuration for the application, engines, and railties goes here.
    #
    # These settings can be overridden in specific environments using the files
    # in config/environments, which are processed later.
    #
    # config.time_zone = "Central Time (US & Canada)"
    # config.eager_load_paths << Rails.root.join("extras")

    # Only loads a smaller set of middleware suitable for API only apps.
    # Middleware like session, flash, cookies can be added back manually.
    # Skip views, helpers and assets when generating a new resource.
    config.api_only = true
    config.after_initialize do
      uncomplete_test_results = Dcc.where(active: '0')
      uncomplete_test_results.each do |test_result|
        Rails.logger.info "A test result polling has started. id:#{test_result["id"]}"
        periodic_function JSON.parse(test_result["dcc"])
      end
    end

    def periodic_function dcc, delay=ENV["CWA_POLLING_INTERVAL_SECS"].to_i
      Thread.new do
        loop do
        test_result = Dcc.find_by(test_id: dcc["cwa_test_id"])
        test_result.update(last_polling_time: Time.now.strftime("%Y-%m-%d %H:%M:%S"))
        
        key = get_pub_keys dcc
        if(key.empty?() == false)
          break
        end
        sleep delay
        end
      end
    end
    
    def get_pub_keys dcc
      # to determin public keys for existing test results(periodic function)
      current_key = {}
      dcc_url = ENV["DCC_URL"]      # DCC server address
      Rails.logger.info "Determination of public keys from dcc server #{dcc_url}..."
  
      client_key = OpenSSL::PKey::RSA.new(File.read(ENV["KEY_PATH"]), ENV["KEY_PASSWORD"])
      client_cert = OpenSSL::X509::Certificate.new(File.read(ENV["CERT_PATH"]))
      dcc_server_connection = Faraday.new dcc_url,
        ssl: {
          client_key: client_key,
          client_cert: client_cert
        } do |c|
          c.use Faraday::Response::RaiseError
        end
      pub_keys_response = dcc_server_connection.get("version/v1/publicKey/search/#{dcc["labId"]}")
  
      data = JSON.parse(pub_keys_response.body)
      testId = Digest::SHA256.hexdigest dcc["cwa_test_id"]
      data.each do |key|
        if(testId == key["testId"])
          test_result = Dcc.find_by(test_id: dcc["cwa_test_id"])
          test_result.update(status: "polled",polled_time: Time.now.strftime("%Y-%m-%d %H:%M:%S"), active: "1")
          Rails.logger.info "A test result was polled. id:#{test_result["id"]}"
          current_key = key
          Rails.logger.info  "DCCid and public keys:#{key}"
          Encrypt_Upload_DCC dcc, key
          break
        end
        Rails.logger.warn "This test result is not requested by CWA App!"
      end
  
      current_key
    end
  
    def Encrypt_Upload_DCC dcc, key
      #4 JSON / DCC-“Kernel“ / Assembled by Partner SW based on exchanged information
      dcc_data = build_DCC_data dcc, key
      Rails.logger.info "DCC JSON object:#{dcc_data}"
  
      #5 DCC data structure(HCERT container)
      cbor_hcert = build_CBOR_HCERT dcc, dcc_data
      Rails.logger.info "HCERT container:#{cbor_hcert}"
  
      # build COSE structure for DCC hash calculation
      dcc_hash_hex = build_COSE_structure cbor_hcert
      Rails.logger.info "dccHashHex:#{dcc_hash_hex}"
  
      # generate 32byte key for AES encryption
      key_32_bytes = generate_32_bytes_key
      Rails.logger.info "AES key:#{key_32_bytes}"
  
      # Encryption of the CBOR from the DCC payload using AES256 (AES / CBC / PKCS5Padding; IV = {0, ..., 0}) -> encryptedDcc
      encrypted_DCC = encrypt_DCC_CBOR cbor_hcert, key_32_bytes
      encrypted_DCC = Base64.encode64(encrypted_DCC)
      encrypted_DCC = encrypted_DCC.gsub("\n", "")
      Rails.logger.info "encrypted DCC:#{encrypted_DCC}"
      
      # Encrypt 32 byte key using public key from step "Determination of public keys for existing test results"
      data_Encryption_Key = encrypt_32_key key_32_bytes, key
      Rails.logger.info "dataEncryptionKey:#{data_Encryption_Key}"
      
      # Send DCC Data to Proxy
      partial_DCC = send_DCC_data dcc_hash_hex, encrypted_DCC, data_Encryption_Key, key
      Rails.logger.info "partialDCC:#{partial_DCC}"
      
    end
  
    def build_DCC_data dcc, key
      # build JSON data schema
      data = {}
      test_data = []
      timestamp = Time.at(dcc["timestamp"]).strftime('%FT%TZ')
  
        test_data.push({
          ci: key["dcci"],
          co: $issuer_country,  # The country of the certificate issuer: DE
          is: $issuer,  # Issuer of the certificate: Robert Koch Institute
          tg: $disease, # Disease: 840539006
          tt: $test_type, # Typ des Tests, Antigentest: LP217198-3
          sc: "#{timestamp}",
          tr: "260415000",          # Negative
          tc: "CovidGo.io",    # site
          ma: @device_id    # Beijing Hotgen
        })
  
      data[:t] = test_data
      data = data.merge({
        dob: dcc["dob"],
        nam: {
          fn: dcc["ln"],
          fnt: convert_string_ICAO(dcc["ln"].upcase),
          gn: dcc["fn"],
          gnt: convert_string_ICAO(dcc["fn"].upcase)
        },
        ver: $version
      })
      
      data
    end
  
    def build_CBOR_HCERT dcc, dcc_data
      # build HCERT container data with JSON schema
      data = {
        1 => "DE",
        4 => dcc["timestamp"] + $expiration_dates*60*60*24,
        6 => dcc["timestamp"],
        -260 => {
          1 => dcc_data
        }
      }
  
      encoded_data = data.to_cbor    # to convert CBOR data format
      byte_arr = encoded_data.unpack("C*")
      cbor_hcert = byte_arr.map{ |byte| byte.to_s(16).force_encoding('iso-8859-1').encode('utf-8').upcase.length == 1 ? "0#{byte.to_s(16).force_encoding('iso-8859-1').encode('utf-8').upcase}":byte.to_s(16).force_encoding('iso-8859-1').encode('utf-8').upcase}.join("")
  
      cbor_hcert
    end
  
    # Assemble COSE structure for dccHash calculation only   
  
    # Creates CBOR for the signing object for the dccHash calculation only 
    # Since the CBOR prefix coding is always the same, just add the CBOR of the HCERT
    # Attention: This just an example - has to be adapted if CBOR HEX > 255 Byte (0xFF)!
    def build_COSE_structure cbor_hcert
      cbor_length = (cbor_hcert.length / 2).to_s(16)
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
  
      dccHashHex = OpenSSL::Digest.digest("SHA256", hexToStr(cbor_cose))
      dccHashHex = bin_to_hex(dccHashHex)
  
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
      aes.key = hexToStr(key_32_bytes)
      aes.iv = hexToStr(iv)
      aes.update(hexToStr(cbor_hcert)) + aes.final
  
      # encryptedDcc
    end
  
    def encrypt_32_key key_32_bytes, key
      # encrypt DEK with Public Key
      public_key = key["publicKey"]
      key = OpenSSL::PKey::RSA.new(Base64.decode64(public_key))
      label = ''
      md_oaep = OpenSSL::Digest::SHA256
      md_mgf1 = OpenSSL::Digest::SHA256
      data_Encryption_Key = key.public_encrypt_oaep(hexToStr(key_32_bytes), label, md_oaep, md_mgf1)
      data_Encryption_Key = Base64.encode64(data_Encryption_Key)
      data_Encryption_Key = data_Encryption_Key.gsub("\n", "")
  
      data_Encryption_Key
    end
  
    def send_DCC_data dcc_hash_hex, encrypted_DCC, data_Encryption_Key, key
      testId = key["testId"]
      dcc_json = {
        dccHash: dcc_hash_hex,
        encryptedDcc: encrypted_DCC,
        dataEncryptionKey: data_Encryption_Key
      }
      dcc_json = dcc_json.to_json
      Rails.logger.info "JSON object for Uploading request:#{dcc_json}"
  
      dcc_url = ENV["DCC_URL"]
  
      client_key = OpenSSL::PKey::RSA.new(File.read(ENV["KEY_PATH"]), ENV["KEY_PASSWORD"])
      client_cert = OpenSSL::X509::Certificate.new(File.read(ENV["CERT_PATH"]))
      dcc_server_connection = Faraday.new dcc_url,
        ssl: {
          client_key: client_key,
          client_cert: client_cert
        } do |c|
          c.use Faraday::Response::RaiseError
        end
      dcc_server_response = dcc_server_connection.post("version/v1/test/#{testId}/dcc") do |request|
        request.headers['Content-Type'] = 'application/json'
        request.body = dcc_json
        Rails.logger.info "request:#{request}"
      end
  
      if(dcc_server_response.success)
        test_result = Dcc.find_by(test_id: dcc["cwa_test_id"])
        test_result.update(success_time: Time.now.strftime("%Y-%m-%d %H:%M:%S"), status: "success", active: "1")
        Rails.logger.info "A test result was successfully uploaded. id:#{test_result["id"]}"
      end
  
      dcc_server_response = JSON.parse(dcc_server_response.body)
      Rails.logger.info "Signature response:#{dcc_server_response}"
  
      dcc_server_response
    end
  
    def bin_to_hex(s)     #strToHex equal to bin2hex in PHP
      s.unpack('H*').first
    end
    
    def hex_to_bin(s)     # hexToStr
      s.scan(/../).map { |x| x.hex }.pack('c*')
    end
  
    def strToHex str
      hex = str.unpack("H*")
      hex
    end
    
    def hexToStr hex
      str = [hex].pack("H*")
      str
    end
  
    def get_deviceID_perday
      Rails.logger.info "Daily retieving the device_id from https://distribution.dcc-rules.de/valuesets/ - Thread initialized"
      Thread.new do
        loop do
          url = "https://distribution.dcc-rules.de/valuesets/";
          response = Faraday.get url
          valuesets = JSON.parse response.body
  
          hash = ""
          valuesets.each do |value|
            if(value["id"] == "covid-19-lab-test-manufacturer-and-name")
              hash = value["hash"]
            end
          end
  
          url = url + hash
          response = Faraday.get url
          rat_lists = JSON.parse response.body
          rat_lists = rat_lists["valueSetValues"]
  
          temp_id = 0
          rat_lists.each do |key, value|
            if(value["display"] == "Beijing Hotgen Biotech Co., Ltd, Novel Coronavirus 2019-nCoV Antigen Test (Colloidal Gold)")
              temp_id = key
            end
          end
          @device_id = temp_id
          Rails.logger.info "device_id: #{@device_id}"
  
          sleep 86400
        end
      end
    end
  
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
      'ß'=>'SS',
      'ẞ'=>'SS',
      'Ä'=>'A',  
      'Ö'=>'O',
      'Ü'=>'U',
      'ä'=>'A',
      'ö'=>'O',
      'ü'=>'U',
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
end
