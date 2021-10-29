Rails.application.routes.draw do
  # For details on the DSL available within this file, see https://guides.rubyonrails.org/routing.html
  # TODO: do we need service versioning ?
  # scope '/v1' do

  get '/health', to: 'health#index'

  # POST /qr_code
  # GET /qr_code/<id>
  resources :qr_code, only: %i[create show]

  # POST /test_result
  resources :test_result, only: %i[create]

  # POST /dcc
  resources :dcc, only: %i[create]
end
