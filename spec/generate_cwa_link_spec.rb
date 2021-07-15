require 'rails_helper'
describe "generate cwa link" do
  context "with anonymous data" do
    it 'generates the correct cwa_link' do
      controller = TestResultController.new
      data = {
        "timestamp": 1618386548,
        "result": 5,
        "anonymous": true
      }
      cwa_data = controller.instance_eval{ generate_cwa_link data, salt = "759F8FF3554F0E1BBF6EFF8DE298D9E9" }
      expect(cwa_data[:cwa_link]).to eq("https://s.coronawarn.app?v=1#eyAidGltZXN0YW1wIjogMTYxODM4NjU0OCwgInNhbHQiOiAiNzU5RjhGRjM1NTRGMEUxQkJGNkVGRjhERTI5OEQ5RTkiLCAiaGFzaCI6ICI4MDIzMjgzODA0NmQyYTY1YWIxYjdhMWJlM2RkMTI1MGJhOWM5MWM5Njk0NzZjMDkzYmMzNDAwMWVmNDYwYWY4IiB9")
    end
  end
  context "with personalized data" do
    it 'generates the correct cwa_link' do
      controller = TestResultController.new
      data = {
        "fn": "Erika",
        "ln": "Mustermann",
        "dob": "1990-12-23",
        "timestamp": 1618386548,
        "testid": "52cddd8e-ff32-4478-af64-cb867cea1db5",
        "result": 5,
        "anonymous": false
      }
      cwa_data = controller.instance_eval{ generate_cwa_link data, salt = "759F8FF3554F0E1BBF6EFF8DE298D9E9" }
      expect(cwa_data[:cwa_link]).to eq("https://s.coronawarn.app?v=1#eyAiZm4iOiAiRXJpa2EiLCAibG4iOiAiTXVzdGVybWFubiIsICJkb2IiOiAiMTk5MC0xMi0yMyIsICJ0aW1lc3RhbXAiOiAxNjE4Mzg2NTQ4LCAidGVzdGlkIjogIjUyY2RkZDhlLWZmMzItNDQ3OC1hZjY0LWNiODY3Y2VhMWRiNSIsICJzYWx0IjogIjc1OUY4RkYzNTU0RjBFMUJCRjZFRkY4REUyOThEOUU5IiwgImhhc2giOiAiNjdhNTBjYmE1OTUyYmY0ZjZjN2VjYTg5NmMwMDMwNTE2YWIyZjIyOGYxNTcyMzc3MTJlNTJkNjY0ODlkOTk2MCIgfQ==")
    end
  end
end