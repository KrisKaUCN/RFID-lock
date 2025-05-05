import asyncio
import sqlite3
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
        logging.FileHandler("rfid_system.log"),
        logging.StreamHandler()
    ]
)

# Global mode variable: "read" for access checking; "write" for enrolling new tags.
current_mode = "read"


# --------------------------------------------------
# 2. Database Initialization with Error Handling
# --------------------------------------------------
def init_db():
    try:
        connection = sqlite3.connect('rfid_tags.db')
        cursor = connection.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS rfid_tags (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                uid TEXT UNIQUE,
                label TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        connection.commit()
        logging.info("Database initialized successfully.")
        return connection, cursor
    except Exception as e:
        logging.critical("Failed to initialize database: %s", e)
        raise


# --------------------------------------------------
# 3. Retry Mechanism for RFID Operations
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
                logging.warning("Operation %s failed with error: %s. Retrying in %.2f sec (attempt %d of %d)",
                                operation.__name__, ex, delay, retries, max_retries)
                await asyncio.sleep(delay)


# --------------------------------------------------
# 4. RFID Polling, Using Nonblocking Asyncio and Retry
# --------------------------------------------------
def poll_for_tag(rdr):
    """
    Polls for a tag using low-level RFID library calls.
    If an error code is returned instead of a tag, an Exception is raised.
    """
    error, tag_type = rdr.request()
    if error:
        raise Exception(f"RFID request error: {error}")
    error_uid, raw_uid = rdr.anticoll()
    if error_uid:
        raise Exception(f"RFID anticoll error: {error_uid}")
    return raw_uid


async def scan_rfid(cursor, connection):
    """
    Continuously polls for RFID tags without blocking the event loop.
    Processes each unique tag based on the current operational mode.
    Wrapped operations are retried if transient errors occur.
    """
    rdr = RFID()
    logging.info("Starting RFID scanning task.")
    last_uid = None
    try:
        while True:
            try:
                # Wrap the polling operation with our retry mechanism.
                raw_uid = await perform_rfid_operation(poll_for_tag, rdr)
                uid_str = '-'.join(map(str, raw_uid))
                # Only process the tag once until it’s removed.
                if uid_str != last_uid:
                    logging.info("New tag detected with UID: %s", uid_str)
                    last_uid = uid_str
                    if current_mode == "read":
                        # Allow/Deny Mode: Query database to check registration.
                        try:
                            cursor.execute("SELECT * FROM rfid_tags WHERE uid = ?", (uid_str,))
                            record = cursor.fetchone()
                            if record:
                                logging.info("Access Allowed! Registered label: %s", record[2])
                            else:
                                logging.info("Access Denied! Tag not found in the database.")
                        except Exception as db_ex:
                            logging.error("Database error during access check: %s", db_ex)
                    elif current_mode == "write":
                        # Enroll Mode: Register a new tag if not already enrolled.
                        try:
                            cursor.execute("SELECT * FROM rfid_tags WHERE uid = ?", (uid_str,))
                            record = cursor.fetchone()
                            if record:
                                logging.info("Tag already registered. Enrollment denied.")
                            else:
                                # Use run_in_executor to make the blocking input() nonblocking.
                                loop = asyncio.get_event_loop()
                                label = await loop.run_in_executor(None, input, "Enter a label for the new tag: ")
                                label = label.strip()
                                if not label:
                                    logging.warning("Empty label input. Skipping enrollment for UID: %s", uid_str)
                                    continue

                                # Prepare data: write "Registered" to block 8.
                                data_text = "Registered"
                                data_bytes = [ord(c) for c in data_text]
                                # Ensure exactly 16 bytes (trim or pad)
                                data_bytes = data_bytes[:16] + [0] * (16 - len(data_bytes))

                                # Perform the authentication and writing with retries.
                                await perform_rfid_operation(rdr.auth, rdr.AUTHENT1A, 8, [0xFF] * 6, raw_uid)
                                await perform_rfid_operation(rdr.write, 8, data_bytes)
                                # Stop encryption; wrap in try/except since it’s final.
                                try:
                                    rdr.stop_crypto()
                                except Exception as ex:
                                    logging.warning("Error during stop_crypto: %s", ex)
                                logging.info("Data written to tag (block 8).")

                                # Insert new tag registration into the database.
                                try:
                                    cursor.execute("INSERT INTO rfid_tags (uid, label) VALUES (?, ?)", (uid_str, label))
                                    connection.commit()
                                    logging.info("New tag enrolled successfully with label: %s", label)
                                except sqlite3.IntegrityError as ie:
                                    logging.warning("Tag insertion failed (IntegrityError): %s", ie)
                                except Exception as db_e:
                                    logging.error("Database error during enrollment: %s", db_e)
                        except Exception as enroll_ex:
                            logging.error("Error in enrollment process: %s", enroll_ex)
            except Exception as e:
                logging.error("RFID polling error: %s", e)
            # Reset last_uid when no tag is detected for a new event.
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
# 5. Asynchronous Command Listener for Mode Switching
# --------------------------------------------------
async def command_listener():
    """
    Listens asynchronously for user commands to switch the system mode.
    Supported commands:
      • "enrollmode" – switch to enrollment (write) mode.
      • "admode" – switch to allow/deny (read) mode.
    """
    global current_mode
    loop = asyncio.get_event_loop()
    logging.info("Starting command listener task.")
    try:
        while True:
            cmd = await loop.run_in_executor(None, input, "Command ('enrollmode' or 'admode'): ")
            cmd = cmd.strip().lower()
            if cmd == "enrollmode":
                current_mode = "write"
                logging.info("Switched to enroll (write) mode.")
            elif cmd == "admode":
                current_mode = "read"
                logging.info("Switched to allow/deny (read) mode.")
            else:
                logging.warning("Unknown command entered: %s", cmd)
            await asyncio.sleep(0.1)
    except asyncio.CancelledError:
        logging.info("Command listener task canceled.")
        raise
    except Exception as e:
        logging.error("Command listener encountered error: %s", e)


# --------------------------------------------------
# 6. Main Application With Task Management and Cancellation
# --------------------------------------------------
async def main():
    connection, cursor = init_db()
    tasks = [
        asyncio.create_task(scan_rfid(cursor, connection)),
        asyncio.create_task(command_listener())
    ]
    try:
        # Gather tasks and wait indefinitely (they run until cancellation).
        await asyncio.gather(*tasks)
    except Exception as e:
        logging.critical("Main tasks encountered an error: %s", e)
    finally:
        # Cancel all tasks on exit and close the database connection.
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        connection.close()
        logging.info("Database connection closed.")

# --------------------------------------------------
# 7. Top-Level Exception Handling and Program Shutdown
# --------------------------------------------------
if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("Program terminated by user (KeyboardInterrupt).")
    except Exception as e:
        logging.critical("Unhandled exception in main: %s", e)
