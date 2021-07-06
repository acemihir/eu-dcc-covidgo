# srv-gw-cwa

CWA integration service. Implementation based on https://github.com/corona-warn-app/cwa-quicktest-onboarding/wiki/Anbindung-der-Partnersysteme

## Configuration

this environment variables need to be set:
```
  SERVER_TOKEN: the authentication token for this service
  KEY_PASSWORD: the password for the key-file
  CWA_URL: the url to the CWA server
  KEY_PATH: the relative path to the key-file
  CERT_PATH: the relative path to the certification-file
  secret_key_base: internal key-base
```
optional:
```
RAILS_LOG_TO_STDOUT: if set to true logging is done to console (else to file)
```

one example could be:
```
  SERVER_TOKEN: MrdmX7WH9rQCcxLb80FDoKPZEMAHbukvmrER1/Ht2JE=
  KEY_PASSWORD: pass
  CWA_URL: https://quicktest-result-dfe4f5c711db.coronawarn.app/
  KEY_PATH: config/credentials/covidgo-wru.key
  CERT_PATH: config/credentials/covidgo-wru.schnelltestportal.de-Server-17f5abbefa6fb59dfa43f1dc8bc4ddfd.cer
  secret_key_base: MrdmX7WH9rQCcxLb80FDoKPZEMAHbukvmrER1/Ht2JE=
```
**Remember to copy the Certificate- and Key-File to the path (KEY_PATH, CERT_PATH).**

### Logging
 if **RAILS_LOG_TO_STDOUT: true** Logging is done to console output.
 else **Logfile is placed at /log/production.log** (for production env).

## Tech-Stack
* Rails 6.1
* Ruby 3.0

## API docs
 see doc/cwa_integration.postman_collection.json

 get QR-code and send test result (you need to set Authentication in Header):

 **request:**

 `POST http://127.0.0.1:3000/test_result`
 ```
 {
    "fn": "Erika",
    "ln": "Mustermann",
    "dob": "1990-12-23",
    "timestamp": 1618386548,
    "testid": "52cddd8e-ff32-4478-af64-cb867cea1db7",
    "result": 5
}
 ```

  **result:**

`Status: 200 OK`
 ```
 {
    "fn": "Erika",
    "ln": "Mustermann",
    "dob": "1990-12-23",
    "timestamp": 1618386548,
    "testid": "52cddd8e-ff32-4478-af64-cb867cea1db7",
    "result": 5,
    "salt": "295047b537543b55656609f8b308b1f3",
    "cwa_test_id": "dfede2d75edf197c5cbe9f4503b1ac0115ee581142000efc4fc17e3b497a728a",
    "cwa_base64_object": "eyAiZm4iOiAiRXJpa2EiLCAibG4iOiAiTXVzdGVybWFubiIsICJkb2IiOiAiMTk5MC0xMi0yMyIsICJ0aW1lc3RhbXAiOiAxNjE4Mzg2NTQ4LCAidGVzdGlkIjogIjUyY2RkZDhlLWZmMzItNDQ3OC1hZjY0LWNiODY3Y2VhMWRiNyIsICJzYWx0IjogIjI5NTA0N2I1Mzc1NDNiNTU2NTY2MDlmOGIzMDhiMWYzIiwgImhhc2giOiAiZGZlZGUyZDc1ZWRmMTk3YzVjYmU5ZjQ1MDNiMWFjMDExNWVlNTgxMTQyMDAwZWZjNGZjMTdlM2I0OTdhNzI4YSIgfQ==",
    "cwa_link": "https://s.coronawarn.app?v=1#eyAiZm4iOiAiRXJpa2EiLCAibG4iOiAiTXVzdGVybWFubiIsICJkb2IiOiAiMTk5MC0xMi0yMyIsICJ0aW1lc3RhbXAiOiAxNjE4Mzg2NTQ4LCAidGVzdGlkIjogIjUyY2RkZDhlLWZmMzItNDQ3OC1hZjY0LWNiODY3Y2VhMWRiNyIsICJzYWx0IjogIjI5NTA0N2I1Mzc1NDNiNTU2NTY2MDlmOGIzMDhiMWYzIiwgImhhc2giOiAiZGZlZGUyZDc1ZWRmMTk3YzVjYmU5ZjQ1MDNiMWFjMDExNWVlNTgxMTQyMDAwZWZjNGZjMTdlM2I0OTdhNzI4YSIgfQ=="
}
 ```


## Authentication
set the following header to the request:
```
  Authorization:System <SERVER_TOKEN>
```

## Example
```
git clone git@gitlab.com:covidgotech/apit/srv-gw-cwa.git
cd srv-gw-cwa
cp <path>/covidgo-wru.* config/credentials
sudo docker build -t srv-gw-cwa:prod .
sudo docker run -p 3000:3000 -e RAILS_LOG_TO_STDOUT=true -e SERVER_TOKEN=MrdmX7WH9rQCcxLb80FDoKPZEMAHbukvmrER1/Ht2JE= -e KEY_PASSWORD=pass -e CWA_URL=https://quicktest-result-dfe4f5c711db.coronawarn.app/ -e KEY_PATH=config/credentials/covidgo-wru.key -e CERT_PATH=config/credentials/covidgo-wru.schnelltestportal.de-Server-17f5abbefa6fb59dfa43f1dc8bc4ddfd.cer -e SECRET_KEY_BASE=MrdmX7WH9rQCcxLb80FDoKPZEMAHbukvmrER1/Ht2JE= srv-gw-cwa:prod
```