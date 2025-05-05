from pirc522 import RFID

rdr = RFID()
rdr.wait_for_tag()
(error, tag_type) = rdr.request()
if not error:
    (error, uid) = rdr.anticoll()
    if not error:
        print("Tag detected! UID:", uid)
        rdr.select_tag(uid)
        key = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]  # Default key
        rdr.auth(rdr.AUTHENT1A, 8, key, uid)  # Authenticate sector
        data = [ord(c) for c in "HelloWorld!"] + [0] * (16 - len("HelloWorld!"))  # Convert text to bytes
        rdr.write(8, data)  # Write to block 8
        rdr.stop_crypto()
        print("Data written successfully!")
