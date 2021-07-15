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

The service has 2 modi with anonymous data and with personalized data.
For the modus with anonymous data there mus be at least the parameter (**timestamp** and **result**). For the modus with personal data there must be **fn**, **ln**, **dob**, **timestamp**, **testid**, **result**. If not all parameter are present, the service switches automatiucly into anonymous modus.
In the request result you get the information in which modus the service ran (**anonymous** is true or false).

 get QR-code and send test result **anonymous** (you need to set Authentication in Header):

 **request:**

 `POST http://127.0.0.1:3000/test_result`
 ```
 {
    "timestamp": 1618386548,
    "result": 5
 }
 ```

  **result:**

`Status: 200 OK`
 ```
 {
   "timestamp": 1618386548,
   "result": 5,
   "anonymous": true,
   "salt": "76afc6f32bdefcdcd5a5a74571c9bb73",
   "cwa_test_id": "e772cecb5ee39a954795d47a534a3710c18cf9c4c3cd446bfa94c5cb78d5d020",
   "cwa_base64_object": "eyAidGltZXN0YW1wIjogMTYxODM4NjU0OCwgInNhbHQiOiAiNzZhZmM2ZjMyYmRlZmNkY2Q1YTVhNzQ1NzFjOWJiNzMiLCAiaGFzaCI6ICJlNzcyY2VjYjVlZTM5YTk1NDc5NWQ0N2E1MzRhMzcxMGMxOGNmOWM0YzNjZDQ0NmJmYTk0YzVjYjc4ZDVkMDIwIiB9",
   "cwa_link": "https://s.coronawarn.app?v=1#eyAidGltZXN0YW1wIjogMTYxODM4NjU0OCwgInNhbHQiOiAiNzZhZmM2ZjMyYmRlZmNkY2Q1YTVhNzQ1NzFjOWJiNzMiLCAiaGFzaCI6ICJlNzcyY2VjYjVlZTM5YTk1NDc5NWQ0N2E1MzRhMzcxMGMxOGNmOWM0YzNjZDQ0NmJmYTk0YzVjYjc4ZDVkMDIwIiB9"
}
 ```

 get QR-code and send test result **personalized** (you need to set Authentication in Header):

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
    "testid": "52cddd8e-ff32-4478-af64-cb867cea1db5",
    "result": 5,
    "anonymous": false,
    "salt": "d2ef253ac725175e02b792ab712b1586",
    "cwa_test_id": "c7bc6a83a5f0ac231a3ddf18962be518e941f11b39c022d9dfbd2f1690e4e0a2",
    "cwa_base64_object": "eyAiZm4iOiAiRXJpa2EiLCAibG4iOiAiTXVzdGVybWFubiIsICJkb2IiOiAiMTk5MC0xMi0yMyIsICJ0aW1lc3RhbXAiOiAxNjE4Mzg2NTQ4LCAidGVzdGlkIjogIjUyY2RkZDhlLWZmMzItNDQ3OC1hZjY0LWNiODY3Y2VhMWRiNSIsICJzYWx0IjogImQyZWYyNTNhYzcyNTE3NWUwMmI3OTJhYjcxMmIxNTg2IiwgImhhc2giOiAiYzdiYzZhODNhNWYwYWMyMzFhM2RkZjE4OTYyYmU1MThlOTQxZjExYjM5YzAyMmQ5ZGZiZDJmMTY5MGU0ZTBhMiIgfQ==",
    "cwa_link": "https://s.coronawarn.app?v=1#eyAiZm4iOiAiRXJpa2EiLCAibG4iOiAiTXVzdGVybWFubiIsICJkb2IiOiAiMTk5MC0xMi0yMyIsICJ0aW1lc3RhbXAiOiAxNjE4Mzg2NTQ4LCAidGVzdGlkIjogIjUyY2RkZDhlLWZmMzItNDQ3OC1hZjY0LWNiODY3Y2VhMWRiNSIsICJzYWx0IjogImQyZWYyNTNhYzcyNTE3NWUwMmI3OTJhYjcxMmIxNTg2IiwgImhhc2giOiAiYzdiYzZhODNhNWYwYWMyMzFhM2RkZjE4OTYyYmU1MThlOTQxZjExYjM5YzAyMmQ5ZGZiZDJmMTY5MGU0ZTBhMiIgfQ=="
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

## Run the tests
```
bundle exec rspec
```