#!/usr/bin/python3
# updater_client.py
#
# An actual device client that connects to the SUIT server. It handles
# firmware updates by passing the received file to an external handler script.

import asyncio
import websockets
import json
import os
import subprocess
import sys
import uuid # Use the built-in uuid module to get the MAC address

# --- Configuration ---
SERVER_URI = "ws://statusserver.com:8765"
VERSION_FILE = "version.info"
INITIAL_VERSION = "1.0.0"
UPDATE_HANDLER_CWD = os.path.realpath(os.path.join(os.path.dirname(__file__), "../secure_update")) # Directory where the update handler script is located
UPDATE_HANDLER_SCRIPT = os.path.join(UPDATE_HANDLER_CWD, "secure_update") # The external script to process the update

def get_device_id():
    """Retrieves the MAC address of the device using the uuid module."""
    try:
        # uuid.getnode() returns the MAC address as a 48-bit integer
        mac_num = uuid.getnode()
        # Format the integer into a 12-character hex string, padded with leading zeros
        mac_hex = '{:012x}'.format(mac_num)
        # Insert colons every two characters to create the standard format
        mac_address = ':'.join(mac_hex[i:i+2] for i in range(0, 12, 2))
        
        # uuid.getnode() can fail on some systems and return a random multicast address.
        # While not a perfect check, if it's all zeros, something is wrong.
        if mac_address == "00:00:00:00:00:00":
             print("ERROR: Could not get a valid MAC address (got all zeros). Exiting.")
             sys.exit(1)

    except Exception as e:
        print(f"ERROR: Could not get MAC address. Error: {e}. Exiting.")
        sys.exit(1)
        
    return mac_address.upper()


def read_version():
    """Reads the current firmware version from the version file."""
    if not os.path.exists(VERSION_FILE):
        write_version(INITIAL_VERSION)
        return INITIAL_VERSION
    with open(VERSION_FILE, 'r') as f:
        return f.read().strip()

def write_version(version):
    """Writes the given version to the version file."""
    with open(VERSION_FILE, 'w') as f:
        f.write(version)
    print(f"Version updated to {version} on disk.")

async def send_status(websocket, status, version):
    """Sends a status update to the server."""
    message = {"status": status, "version": version}
    try:
        await websocket.send(json.dumps(message))
        print(f"Sent status: {status}")
    except websockets.exceptions.ConnectionClosed:
        print("Could not send status, connection is closed.")


async def run_client():
    """Main function to run the device client."""
    device_id = get_device_id()
    current_version = read_version()

    print(f"--- SUIT Updater Client ---")
    print(f"Device ID (MAC): {device_id}")
    print(f"Current Version: {current_version}")
    print(f"Connecting to server: {SERVER_URI}")
    print(f"---------------------------")

    async with websockets.connect(SERVER_URI) as websocket:
        # 1. Announce ourselves to the server
        initial_message = {
            "device_id": device_id,
            "current_version": current_version
        }
        await websocket.send(json.dumps(initial_message))

        # 2. Main loop to listen for commands from the server
        while True:
            try:
                message = await websocket.recv()

                if isinstance(message, str):
                    command_data = json.loads(message)
                    if command_data.get("command") == "update":
                        print("\nReceived 'update' command.")
                        new_version = command_data['version']
                        file_size = command_data['size']
                        temp_firmware_file = f"/tmp/temp_firmware_{new_version}.bin"

                        await send_status(websocket, "downloading", current_version)

                        # Receive the firmware file binary data
                        bytes_received = 0
                        with open(temp_firmware_file, 'wb') as f:
                            while bytes_received < file_size:
                                chunk = await websocket.recv()
                                f.write(chunk)
                                bytes_received += len(chunk)
                                print(f"Downloading... {bytes_received}/{file_size} bytes", end='\r')
                        print("\nDownload complete.")

                        # Pass the file to the external update handler
                        await send_status(websocket, "installing", current_version)
                        print(f"Executing external update handler: {UPDATE_HANDLER_SCRIPT}")
                        
                        # Use subprocess to call the external script and wait for it to complete
                        cmd = [UPDATE_HANDLER_SCRIPT, "update", temp_firmware_file]
                        print(f"Running command: {' '.join(cmd)} in {UPDATE_HANDLER_CWD}")
                        process = subprocess.run(
                            cmd,
                            capture_output=True, text=True, cwd=UPDATE_HANDLER_CWD
                        )
                        
                        print("--- Handler Script Output ---")
                        print(process.stdout)
                        if process.stderr:
                            print("--- Handler Script Error ---")
                            print(process.stderr)
                        print("-----------------------------")


                        # Check the return code to determine success or failure
                        if process.returncode == 0:
                            print("Update handler reported SUCCESS.")
                            current_version = new_version
                            write_version(current_version)
                            await send_status(websocket, "success", current_version)
                        else:
                            print(f"Update handler reported FAILURE (exit code: {process.returncode}).")
                            await send_status(websocket, f"failed:install_code_{process.returncode}", current_version)
                        
                        # Clean up the temporary file
                        os.remove(temp_firmware_file)
                        print(f"Cleaned up temporary file: {temp_firmware_file}")

                        if process.returncode == 0:
                            print(f"Rebooting device to apply new version {current_version} in 10 seconds...\n")
                            await asyncio.sleep(10)
                            os.system('reboot')

            except websockets.exceptions.ConnectionClosed:
                print("\nConnection to server closed.")
                break
            except Exception as e:
                print(f"\nAn error occurred: {e}")
                break

async def main():
    while True:
        try:
            await run_client()
        except ConnectionRefusedError:
            print(f"Connection refused. Is the server running at {SERVER_URI}?")
            print("Retrying in 5 seconds...")
            await asyncio.sleep(5)
        except Exception as e:
            print(f"A critical error occurred: {e}")
            exit(1)

if __name__ == "__main__":
    if not os.path.exists(UPDATE_HANDLER_SCRIPT):
        print(f"Error: The update handler script '{UPDATE_HANDLER_SCRIPT}' was not found.")
        print("Please create it or ensure it's in the same directory.")
    else:
        asyncio.run(main())
