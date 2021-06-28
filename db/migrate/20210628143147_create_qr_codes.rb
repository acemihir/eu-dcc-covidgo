class CreateQrCodes < ActiveRecord::Migration[6.1]
  def change
    create_table :qr_codes do |t|
      t.string :fn
      t.string :ln
      t.date :dob
      t.string :testid
      t.timestamp :timestamp
      t.string :cwa_test_id
      t.string :cwa_base64_object

      t.timestamps
    end
  end
end
