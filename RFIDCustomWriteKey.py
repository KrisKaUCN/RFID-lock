from pirc522 import RFID

rdr = RFID()
rdr.wait_for_tag()
(error, tag_type) = rdr.request()
if not error:
    (error, uid) = rdr.anticoll()
    if not error:
        print("Tag detected! UID:", uid)
        rdr.select_tag(uid)
        
        # Default authentication key
        default_key = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
        rdr.auth(rdr.AUTHENT1A, 7, default_key, uid)  # Authenticate sector trailer
        
        # New custom key (change these values)
        new_key = [0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6]
        
        # Access bits (define permissions)
        access_bits = [0xFF, 0x07, 0x80, 0x69]  # Example access control settings
        
        # Construct sector trailer block (new key + access bits + Key B)
        sector_trailer = new_key + access_bits + new_key
        
        # Write new key to sector trailer
        rdr.write(7, sector_trailer)
        rdr.stop_crypto()
        
        print("Custom key set successfully!")


# To set a custom key, you need to modify the sector trailer (the last block in each sector).
# Explanation:

# Authenticate the sector trailer using the default key.

# Define a new key (change the values for security).

# Set access bits to control read/write permissions.

# Write the new key to the sector trailer block.


# Using the Custom Key

# Once set, you must use the new key for authentication:
# rdr.auth(rdr.AUTHENT1A, 8, new_key, uid)
