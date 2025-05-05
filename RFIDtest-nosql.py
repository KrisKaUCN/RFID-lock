import asyncio
import logging
import time
from pirc522 import RFID

# --------------------------------------------------
# 1. Logging Configuration
# --------------------------------------------------
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("rfid_test.log"),
        logging.StreamHandler()
    ]
)

# Global mode: "read" for access control, "write" for enrollment.
current_mode = "read"

# Simulated database (in-memory dictionary) for testing.
# Key: UID (as a string), Value: label (user string).
known_tags = {}

# --------------------------------------------------
# 2. Retry Mechanism for RFID Operations
# --------------------------------------------------
async def perform_rfid_operation(operation, *args, max_retries=3, base_delay=0.5, **kwargs):
    """
    Calls a synchronous operation that might fail, retrying with exponential backoff.
    """
    retries = 0
    while True:
        try:
            result = operation(*args, **kwargs)
            return result
        except Exception as ex:
            retries += 1
            if retries > max_retries:
                logging.error("Operation %s failed after %d retries: %s", operation.__name__, max_retries, ex)
                raise
            else:
                delay = base_delay * (2 ** (retries - 1))
                logging.warning("Operation %s failed: %s. Retrying in %.2f sec (attempt %d of %d)",
                                operation.__name__, ex, delay, retries, max_retries)
                await asyncio.sleep(delay)

# --------------------------------------------------
# 3. RFID Polling Function (Nonblocking)
# --------------------------------------------------
def poll_for_tag(rdr):
    """
    Poll the RFID reader for a tag and return its raw UID.
    Raise an Exception if no tag is found.
    """
    error, tag_type = rdr.request()
    if error:
        raise Exception(f"RFID request error: {error}")
    error_uid, raw_uid = rdr.anticoll()
    if error_uid:
        raise Exception(f"RFID anticoll error: {error_uid}")
    return raw_uid

# --------------------------------------------------
# 4. Async RFID Scanning Task
# --------------------------------------------------
async def scan_rfid():
    """
    Continuously poll the RFID reader in a nonblocking loop.
    Based on the current_mode global variable, process tags as:
      - "read" mode: simply report if the tag is in known_tags.
      - "write" mode: if the tag isn't registered, prompt for a label,
                      write a marker to the tag, and record it in known_tags.
    """
    rdr = RFID()
    logging.info("Starting RFID scanning task.")
    last_uid = None  # To avoid reprocessing the same tag repeatedly.
    try:
        while True:
            try:
                raw_uid = await perform_rfid_operation(poll_for_tag, rdr)
                uid_str = '-'.join(map(str, raw_uid))
                # Only process if a new card is detected.
                if uid_str != last_uid:
                    logging.info("Tag detected with UID: %s", uid_str)
                    last_uid = uid_str
                    if current_mode == "read":
                        # Allow/Deny mode: check if the tag is known.
                        if uid_str in known_tags:
                            logging.info("Access Allowed! Registered label: %s", known_tags[uid_str])
                        else:
                            logging.info("Access Denied! Tag not recognized.")
                    elif current_mode == "write":
                        # Enroll mode: Check if not already enrolled.
                        if uid_str in known_tags:
                            logging.info("Tag already enrolled. Skipping enrollment.")
                        else:
                            loop = asyncio.get_event_loop()
                            label = await loop.run_in_executor(None, input, "Enter a label for the new tag: ")
                            label = label.strip()
                            if not label:
                                logging.warning("Empty label provided. Skipping enrollment for UID: %s", uid_str)
                                continue
                            # Prepare the marker "Registered"
                            data_text = "Registered"
                            data_bytes = [ord(c) for c in data_text]
                            # Ensure exactly 16 bytes (pad or trim as needed)
                            data_bytes = (data_bytes[:16] + [0]*16)[:16]
                            
                            # Authenticate and write to block 8 using the default key.
                            default_key = [0xFF] * 6
                            await perform_rfid_operation(rdr.auth, rdr.AUTHENT1A, 8, default_key, raw_uid)
                            await perform_rfid_operation(rdr.write, 8, data_bytes)
                            try:
                                rdr.stop_crypto()
                            except Exception as ex:
                                logging.warning("Error during stop_crypto: %s", ex)
                            
                            # Save the tag in the in-memory "database".
                            known_tags[uid_str] = label
                            logging.info("New tag enrolled with label: %s", label)
            except Exception as e:
                logging.error("RFID polling error: %s", e)
            await asyncio.sleep(0.2)
    except asyncio.CancelledError:
        logging.info("RFID scanning task canceled.")
        raise
    except Exception as e:
        logging.critical("RFID scanning task encountered a fatal error: %s", e)
    finally:
        try:
            rdr.cleanup()
            logging.info("RFID reader cleanup completed.")
        except Exception as cleanup_err:
            logging.error("Error during RFID cleanup: %s", cleanup_err)

# --------------------------------------------------
# 5. Async Command Listener Task
# --------------------------------------------------
async def command_listener():
    """
    Listens asynchronously for commands to switch modes.
    Enter "enrollmode" to switch to enrollment mode ("write"),
    or "admode" to switch to access check mode ("read").
    """
    global current_mode
    loop = asyncio.get_event_loop()
    logging.info("Starting command listener task.")
    try:
        while True:
            cmd = await loop.run_in_executor(None, input, "Enter command ('enrollmode' or 'admode'): ")
            cmd = cmd.strip().lower()
            if cmd == "enrollmode":
                current_mode = "write"
                logging.info("Switched to enroll (write) mode.")
            elif cmd == "admode":
                current_mode = "read"
                logging.info("Switched to allow/deny (read) mode.")
            else:
                logging.warning("Unknown command: %s", cmd)
            await asyncio.sleep(0.1)
    except asyncio.CancelledError:
        logging.info("Command listener task canceled.")
        raise
    except Exception as e:
        logging.error("Command listener encountered an error: %s", e)

# --------------------------------------------------
# 6. Main Application: Task Management and Cancellation
# --------------------------------------------------
async def main():
    tasks = [
        asyncio.create_task(scan_rfid()),
        asyncio.create_task(command_listener())
    ]
    try:
        await asyncio.gather(*tasks)
    except Exception as e:
        logging.critical("Main tasks encountered an error: %s", e)
    finally:
        # Cancel tasks at shutdown.
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        logging.info("Exiting application.")

# --------------------------------------------------
# 7. Top-Level Exception Handling and Shutdown
# --------------------------------------------------
if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("Program terminated by user (KeyboardInterrupt).")
    except Exception as e:
        logging.critical("Unhandled exception in main: %s", e)
