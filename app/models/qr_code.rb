class QrCode < ApplicationRecord
  # TODO:validation
  validates_presence_of :fn, :ln, :dob, :testid, :timestamp, :cwa_test_id, :cwa_base64_object
  validates :testid, uniqueness: true
end
