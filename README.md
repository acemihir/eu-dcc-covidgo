# srv-gw-cwa

CWA integration service. Implementation based on https://github.com/corona-warn-app/cwa-quicktest-onboarding/wiki/Anbindung-der-Partnersysteme

## Configuration
this environment variables need to be set:
* SERVER_TOKEN: the authentication token for this service
* KEY_PASSWORD: the password for the key-file
* CWA_URL: the url to the CWA server
* KEY_PATH: the relative path to the key-file
* CERT_PATH: the relative path to the certification-file

one example could be:

* SERVER_TOKEN: MrdmX7WH9rQCcxLb80FDoKPZEMAHbukvmrER1/Ht2JE=
* KEY_PASSWORD: pass
* CWA_URL: https://quicktest-result-dfe4f5c711db.coronawarn.app/
* KEY_PATH: config/credentials/covidgo-wru.key
* CERT_PATH: config/credentials/covidgo-wru.schnelltestportal.de-Server-17f5abbefa6fb59dfa43f1dc8bc4ddfd.cer

## Tech-Stack
* Rails 6.1
* Ruby 3.0

## API docs
 TODO

### Authentication
TODO