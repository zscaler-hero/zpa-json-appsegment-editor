#!/usr/bin/env python3
"""
ZPA Application Segment Editor
Manages Zscaler Private Access application segments through JSON files
"""

import json
import os
import sys
import argparse
import logging
from typing import List, Dict, Any
from datetime import datetime
from dotenv import load_dotenv
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

# Load environment variables
load_dotenv()

# Disable debug logging from libraries
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("requests").setLevel(logging.WARNING)

# Configure logging
log_file = "zpa_editor.log"

# Create formatters
file_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
console_formatter = logging.Formatter("%(levelname)s - %(message)s")

# Create file handler - will be configured based on debug flag
file_handler = logging.FileHandler(log_file)
file_handler.setFormatter(file_formatter)

# Create console handler with INFO level
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(console_formatter)

# Create custom logger (not using root logger to avoid interference)
logger = logging.getLogger("zpa_editor")
logger.setLevel(logging.DEBUG)
logger.handlers = []  # Clear any existing handlers
logger.addHandler(file_handler)
logger.addHandler(console_handler)

# Prevent propagation to root logger
logger.propagate = False

# Initially set file handler to INFO (will be changed to DEBUG if --debug is used)
file_handler.setLevel(logging.INFO)

# Log startup info (only to file)
logger.debug("=" * 60)
logger.debug("ZPA Application Segment Editor Starting")
logger.debug(f"Log file: {log_file}")
logger.debug(f"Working directory: {os.getcwd()}")
logger.debug("=" * 60)

# Constants
JSON_FILE = "application_segments.json"
PAGE_SIZE = 100


class ZPAClient:
    """Client for interacting with Zscaler ZPA API"""

    def __init__(self):
        self.client_id = os.getenv("CLIENT_ID")
        self.client_secret = os.getenv("CLIENT_SECRET")
        self.identity_base_url = os.getenv("IDENTITY_BASE_URL", "").rstrip("/")
        self.customer_id = os.getenv("CUSTOMER_ID")

        if not all(
            [
                self.client_id,
                self.client_secret,
                self.identity_base_url,
                self.customer_id,
            ]
        ):
            raise ValueError("Missing required environment variables. Check .env file.")

        # OAuth and API URLs
        self.token_url = f"{self.identity_base_url}/oauth2/v1/token"
        self.api_base_url = "https://api.zsapi.net"

        self.session = self._create_session()
        self.access_token = None

        logger.debug(
            f"ZPAClient initialized with identity URL: {self.identity_base_url}"
        )

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - close session"""
        self.close()

    def close(self):
        """Close the session"""
        if self.session:
            self.session.close()
            logger.debug("Session closed")

    def _create_session(self) -> requests.Session:
        """Create a session with retry logic"""
        session = requests.Session()
        retry = Retry(
            total=3,
            read=3,
            connect=3,
            backoff_factor=0.3,
            status_forcelist=(500, 502, 504),
        )
        adapter = HTTPAdapter(max_retries=retry)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session

    def authenticate(self) -> None:
        """Authenticate with ZPA API using OAuth 2.0 client credentials flow"""
        logger.info("Authenticating with Zscaler One API...")
        logger.debug(f"Token URL: {self.token_url}")
        logger.debug(
            f"Client ID: {self.client_id[:10]}..."
            if self.client_id
            else "Client ID not set"
        )

        # OAuth 2.0 Client Credentials with audience parameter
        auth_data = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "audience": "https://api.zscaler.com",
        }

        headers = {"Content-Type": "application/x-www-form-urlencoded"}

        logger.debug(f"Authentication request URL: {self.token_url}")
        logger.debug(f"Authentication request headers: {headers}")
        # Log auth data but mask sensitive info
        safe_auth_data = auth_data.copy()
        if "client_secret" in safe_auth_data:
            safe_auth_data["client_secret"] = "***masked***"
        logger.debug(f"Authentication request data: {safe_auth_data}")

        try:
            response = self.session.post(
                self.token_url, headers=headers, data=auth_data, timeout=30
            )

            if response.status_code != 200:
                logger.error(
                    f"Authentication failed with status {response.status_code}"
                )
                logger.debug(f"Response headers: {response.headers}")
                logger.debug(f"Response body: {response.text}")

                # Common error patterns
                if response.status_code == 400:
                    logger.error(
                        "400 Bad Request - Check credentials and IDENTITY_BASE_URL"
                    )
                    logger.debug("Common causes:")
                    logger.debug("  1. Invalid client_id or client_secret")
                    logger.debug(
                        "  2. Wrong IDENTITY_BASE_URL (should be like https://yourcompany.zslogin.net)"
                    )
                    logger.debug(
                        "  3. Credentials not properly configured for OAuth 2.0"
                    )
                elif response.status_code == 401:
                    logger.error(
                        "401 Unauthorized - Check if credentials are valid and active"
                    )

            response.raise_for_status()

            token_data = response.json()
            self.access_token = token_data.get("access_token")

            if not self.access_token:
                logger.error("No access token received from authentication response")
                logger.debug(f"Token response data: {token_data}")
                raise ValueError("No access token received")

            # Set authorization header for future requests
            self.session.headers.update(
                {"Authorization": f"Bearer {self.access_token}"}
            )

            expires_in = token_data.get("expires_in", "Unknown")
            logger.info(f"Authentication successful (expires in {expires_in} seconds)")
            logger.debug(
                f"Token (first 20 chars): {self.access_token[:20]}..."
                if self.access_token
                else "No token"
            )

        except requests.exceptions.RequestException as e:
            logger.error(f"Authentication failed: {e}")
            if hasattr(e, "response") and e.response is not None:
                logger.debug(f"Error response status: {e.response.status_code}")
                logger.debug(f"Error response headers: {dict(e.response.headers)}")
                logger.debug(f"Error response body: {e.response.text}")
            raise

    def get_application_segments(self) -> List[Dict[str, Any]]:
        """Fetch all application segments from ZPA"""
        segments = []
        page = 1

        while True:
            url = f"{self.api_base_url}/zpa/mgmtconfig/v1/admin/customers/{self.customer_id}/application"
            params = {"page": page, "pagesize": PAGE_SIZE}

            try:
                logger.debug(f"Fetching segments - URL: {url}")
                logger.debug(f"Request params: {params}")
                logger.debug(f"Request headers: {dict(self.session.headers)}")

                response = self.session.get(url, params=params)
                response.raise_for_status()

                data = response.json()
                app_segments = data.get("list", [])

                if not app_segments:
                    break

                segments.extend(app_segments)
                logger.info(f"Retrieved page {page} with {len(app_segments)} segments")

                # Check if there are more pages
                if len(app_segments) < PAGE_SIZE:
                    break

                page += 1

            except requests.exceptions.RequestException as e:
                logger.error(f"Failed to fetch application segments: {e}")
                if hasattr(e, "response") and e.response is not None:
                    logger.debug(f"Response status: {e.response.status_code}")
                    logger.debug(f"Response headers: {dict(e.response.headers)}")
                    logger.debug(f"Response body: {e.response.text}")
                raise

        logger.info(f"Total application segments retrieved: {len(segments)}")
        return segments

    def update_application_segment(
        self, segment_id: str, segment_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update a specific application segment"""
        url = f"{self.api_base_url}/zpa/mgmtconfig/v1/admin/customers/{self.customer_id}/application/{segment_id}"

        try:
            logger.debug(f"Updating segment - URL: {url}")
            logger.debug(f"Request headers: {dict(self.session.headers)}")
            # Log segment data but truncate if too long
            data_str = str(segment_data)
            if len(data_str) > 1000:
                logger.debug(f"Request data (truncated): {data_str[:1000]}...")
            else:
                logger.debug(f"Request data: {segment_data}")

            response = self.session.put(url, json=segment_data)
            response.raise_for_status()

            logger.info(
                f"Successfully updated segment: {segment_data.get('name', segment_id)}"
            )

            # Check if response has content before parsing JSON
            if response.text:
                return response.json()
            else:
                # Some APIs return 204 No Content on successful updates
                logger.debug("Update successful but no response body returned")
                return {}

        except requests.exceptions.JSONDecodeError as e:
            logger.error(f"Invalid JSON response for segment {segment_id}")
            logger.debug(f"JSON decode error: {e}")
            logger.debug(f"Response status: {response.status_code}")
            logger.debug(f"Response headers: {dict(response.headers)}")
            logger.debug(f"Response text: {response.text}")
            raise
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to update segment {segment_id}: {e}")
            if hasattr(e, "response") and e.response is not None:
                logger.debug(f"Response status: {e.response.status_code}")
                logger.debug(f"Response headers: {dict(e.response.headers)}")
                logger.debug(f"Response text: {e.response.text}")
            raise


def download_segments(client: ZPAClient) -> None:
    """Download all application segments and save to JSON file"""
    logger.info("Starting download of application segments...")

    # Authenticate
    client.authenticate()

    # Get all segments
    segments = client.get_application_segments()

    # Add metadata
    data = {
        "metadata": {
            "downloaded_at": datetime.now().isoformat(),
            "total_segments": len(segments),
            "customer_id": client.customer_id,
        },
        "segments": segments,
    }

    # Save to file
    with open(JSON_FILE, "w") as f:
        json.dump(data, f, indent=2)

    logger.info(f"Successfully saved {len(segments)} segments to {JSON_FILE}")


def load_local_segments() -> Dict[str, Any]:
    """Load segments from local JSON file"""
    if not os.path.exists(JSON_FILE):
        raise FileNotFoundError(f"{JSON_FILE} not found. Run 'download' first.")

    with open(JSON_FILE, "r") as f:
        return json.load(f)


def compare_segments(local: Dict[str, Any], remote: Dict[str, Any]) -> Dict[str, Any]:
    """Compare two segment objects and return differences"""
    differences = {}

    # Keys to compare (excluding system-managed fields)
    compare_keys = [
        "name",
        "description",
        "enabled",
        "domainNames",
        "serverGroups",
        "tcpPortRanges",
        "udpPortRanges",
        "icmpAccessType",
        "ipAnchored",
        "healthReporting",
        "bypassType",
        "configSpace",
        "defaultIdleTimeout",
        "defaultMaxAge",
        "sraAppsDto",
        "tcpKeepAlive",
    ]

    for key in compare_keys:
        local_val = local.get(key)
        remote_val = remote.get(key)

        if local_val != remote_val:
            differences[key] = {"local": local_val, "remote": remote_val}

    return differences


def preview_diff(client: ZPAClient) -> None:
    """Preview differences between local and remote segments without updating"""
    logger.info("Previewing differences between local and remote segments...")

    try:
        # Load local data
        local_data = load_local_segments()
        local_segments = {seg["id"]: seg for seg in local_data["segments"]}

        # Authenticate and get current remote segments
        client.authenticate()
        remote_segments_list = client.get_application_segments()
        remote_segments = {seg["id"]: seg for seg in remote_segments_list}

        # Track all changes
        added_segments = []
        removed_segments = []
        modified_segments = []

        # Find added and modified segments
        for seg_id, local_seg in local_segments.items():
            if seg_id not in remote_segments:
                added_segments.append(local_seg)
            else:
                differences = compare_segments(local_seg, remote_segments[seg_id])
                if differences:
                    modified_segments.append(
                        {
                            "name": local_seg.get("name", "Unknown"),
                            "differences": differences,
                        }
                    )

        # Find removed segments
        for seg_id, remote_seg in remote_segments.items():
            if seg_id not in local_segments:
                removed_segments.append(remote_seg)

        # Display summary
        print("\n" + "=" * 60)
        print("DIFF SUMMARY: Local JSON vs ZPA")
        print("=" * 60)

        total_changes = (
            len(added_segments) + len(removed_segments) + len(modified_segments)
        )

        if total_changes == 0 and len(removed_segments) == 0:
            print("\n✓ No differences found. Local and remote are in sync.")
            return

        print(
            f"\nTotal changes detected: {len(added_segments) + len(modified_segments)}"
        )
        print(f"  • Added locally: {len(added_segments)}")
        print(f"  • Modified: {len(modified_segments)}")

        if removed_segments:
            print(
                f"\n⚠️  WARNING: {len(removed_segments)} segments exist in ZPA but not in local JSON"
            )
            print("   These segments will NOT be deleted (deletions are not supported)")

        # Show details
        if added_segments:
            print("\n" + "-" * 40)
            print("SEGMENTS ADDED LOCALLY:")
            print("-" * 40)
            for seg in added_segments:
                print(
                    f"  + {seg.get('name', 'Unknown')} (ID: {seg.get('id', 'Unknown')})"
                )

        if removed_segments:
            print("\n" + "-" * 40)
            print("⚠️  SEGMENTS MISSING FROM LOCAL JSON (WILL NOT BE DELETED):")
            print("-" * 40)
            for seg in removed_segments:
                print(
                    f"  ! {seg.get('name', 'Unknown')} (ID: {seg.get('id', 'Unknown')})"
                )

        if modified_segments:
            print("\n" + "-" * 40)
            print("SEGMENTS MODIFIED:")
            print("-" * 40)
            for seg in modified_segments:
                print(f"\n  ~ {seg['name']}")
                # Show field summary
                fields_changed = list(seg["differences"].keys())
                if len(fields_changed) <= 3:
                    print(f"    Changed fields: {', '.join(fields_changed)}")
                else:
                    print(
                        f"    Changed fields: {', '.join(fields_changed[:3])}, and {len(fields_changed)-3} more..."
                    )

        print("\n" + "=" * 60)
        print("Use 'Update application segments' option to apply these changes")

    except FileNotFoundError:
        print(f"\nError: {JSON_FILE} not found. Please download segments first.")
    except Exception as e:
        logger.error(f"Error previewing diff: {e}")
        print(f"\nError: {e}")


def show_diff(segment_name: str, differences: Dict[str, Any]) -> None:
    """Display differences in a readable format"""
    print(f"\n{'='*60}")
    print(f"Segment: {segment_name}")
    print(f"{'='*60}")

    for field, values in differences.items():
        print(f"\nField: {field}")
        print(f"  Current (Remote): {json.dumps(values['remote'], indent=4)}")
        print(f"  New (Local):      {json.dumps(values['local'], indent=4)}")


def confirm_update() -> str:
    """Ask user to confirm update"""
    while True:
        response = input("\nApply this change? (y/n/a/q): ").lower()
        if response in ["y", "n", "a", "q"]:
            return response
        else:
            print("Please enter 'y' for yes, 'n' for no, 'a' for all, or 'q' to quit")


def update_segments(client: ZPAClient, debug: bool = False) -> None:
    """Compare local changes with remote and apply updates"""
    logger.info("Starting update process...")

    # Load local data
    local_data = load_local_segments()
    local_segments = {seg["id"]: seg for seg in local_data["segments"]}

    # Authenticate and get current remote segments
    client.authenticate()
    remote_segments_list = client.get_application_segments()
    remote_segments = {seg["id"]: seg for seg in remote_segments_list}

    # Check for segments that exist remotely but not locally
    missing_segments = []
    for seg_id, remote_seg in remote_segments.items():
        if seg_id not in local_segments:
            missing_segments.append(remote_seg)

    if missing_segments:
        print("\n" + "=" * 60)
        print("⚠️  WARNING: Segments Missing from Local JSON")
        print("=" * 60)
        print(
            f"\nThe following {len(missing_segments)} segments exist in ZPA but not in your local JSON:"
        )
        for seg in missing_segments:
            print(f"  ! {seg.get('name', 'Unknown')} (ID: {seg.get('id', 'Unknown')})")
        print(
            "\n⚠️  These segments will NOT be deleted. This tool does not support deletions."
        )
        print("If you need to delete segments, please use the ZPA console.")
        input("\nPress Enter to continue with updates...")

    # Find changed segments
    changed_segments = []
    for seg_id, local_seg in local_segments.items():
        if seg_id in remote_segments:
            differences = compare_segments(local_seg, remote_segments[seg_id])
            if differences:
                changed_segments.append(
                    {
                        "id": seg_id,
                        "name": local_seg.get("name", "Unknown"),
                        "differences": differences,
                        "local": local_seg,
                        "remote": remote_segments[seg_id],
                    }
                )

    if not changed_segments:
        logger.info("No changes detected between local and remote segments")
        if not missing_segments:
            print("No changes to apply.")
        return

    print(f"\nFound {len(changed_segments)} segments with changes")
    print("Options: [y]es, [n]o, [a]ll (apply all changes), [q]uit")

    # Process each changed segment
    updated_count = 0
    apply_all = False

    for i, segment in enumerate(changed_segments):
        show_diff(segment["name"], segment["differences"])

        if apply_all:
            # Already confirmed to apply all
            apply_change = True
        else:
            response = confirm_update()
            if response == "q":
                print("Quitting update process...")
                break
            elif response == "a":
                # Ask for double confirmation
                print(
                    f"\n⚠️  WARNING: This will apply ALL {len(changed_segments) - i} remaining changes!"
                )
                print("Are you absolutely sure you want to apply all changes?")
                confirm_all = (
                    input("Type 'yes' to confirm, anything else to cancel: ")
                    .strip()
                    .lower()
                )
                if confirm_all == "yes":
                    apply_all = True
                    apply_change = True
                    print("Applying all remaining changes...")
                else:
                    print(
                        "Cancelled 'apply all'. Continuing with individual confirmations."
                    )
                    apply_change = False
            elif response == "y":
                apply_change = True
            else:  # 'n'
                apply_change = False

        if apply_change:
            try:
                # Prepare update data (use local version)
                update_data = segment["local"].copy()
                # Remove read-only fields
                for field in [
                    "id",
                    "creationTime",
                    "modifiedTime",
                    "modifiedBy",
                    "createdBy",
                ]:
                    update_data.pop(field, None)

                client.update_application_segment(segment["id"], update_data)
                updated_count += 1
                print(f"✓ Updated {segment['name']}")
            except Exception as e:
                print(f"✗ Failed to update {segment['name']}: {e}")
                if debug:
                    logger.debug("Full exception details:", exc_info=True)
                # If in apply_all mode, ask if we should continue
                if apply_all:
                    cont = input(
                        "\nError occurred. Continue with remaining updates? (y/n): "
                    ).lower()
                    if cont != "y":
                        print("Stopping update process.")
                        break
        else:
            print(f"⚬ Skipped {segment['name']}")

    print(
        f"\nUpdate complete. Updated {updated_count} out of {len(changed_segments)} changed segments"
    )


def extract_server_groups(segments: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Extract all unique server groups from segments"""
    server_groups = {}

    for segment in segments:
        for sg in segment.get("serverGroups", []):
            if isinstance(sg, dict) and "id" in sg:
                sg_id = sg["id"]
                if sg_id not in server_groups:
                    server_groups[sg_id] = {
                        "id": sg_id,
                        "name": sg.get("name", "Unknown"),
                        "count": 0,
                        "data": sg,
                    }
                server_groups[sg_id]["count"] += 1

    # Return sorted by name
    return sorted(server_groups.values(), key=lambda x: x["name"])


def search_segments_by_name(
    segments: List[Dict[str, Any]], search_str: str
) -> List[Dict[str, Any]]:
    """Search segments by name (case-insensitive)"""
    search_lower = search_str.lower()
    matching_segments = []

    for segment in segments:
        name = segment.get("name", "").lower()
        if search_lower in name:
            matching_segments.append(segment)

    return matching_segments


def check_matchstyle_support(segments: List[Dict[str, Any]]) -> bool:
    """Check if any segment has matchStyle property"""
    for segment in segments:
        if "matchStyle" in segment:
            return True
    return False


def search_segments_with_matchstyle(
    segments: List[Dict[str, Any]], search_str: str
) -> List[Dict[str, Any]]:
    """Search segments by name or matchStyle filter"""
    search_lower = search_str.lower().strip()

    # Check if it's a matchStyle filter
    if search_lower.startswith("matchstyle:"):
        style = search_lower.replace("matchstyle:", "").strip().upper()
        if style in ["INCLUSIVE", "EXCLUSIVE"]:
            return [seg for seg in segments if seg.get("matchStyle") == style]
        else:
            # Invalid matchStyle value, return empty
            return []

    # Otherwise, do regular name search
    return search_segments_by_name(segments, search_str)


def segment_has_server_group(segment: Dict[str, Any], server_group_id: str) -> bool:
    """Check if segment has a specific server group"""
    for sg in segment.get("serverGroups", []):
        if isinstance(sg, dict) and sg.get("id") == server_group_id:
            return True
    return False


def manage_server_groups_local():
    """Manage server groups in local JSON file"""
    try:
        # Load segments
        data = load_local_segments()
        segments = data["segments"]

        if not segments:
            print("\nNo segments found in JSON file.")
            return

        # Check if matchStyle is supported
        has_matchstyle = check_matchstyle_support(segments)

        # Extract server groups
        server_groups = extract_server_groups(segments)

        if not server_groups:
            print("\nNo server groups found in segments.")
            return

        # Select server group
        print("\n" + "=" * 60)
        print("Server Group Management (Local JSON)")
        print("=" * 60)
        print("\nAvailable Server Groups:")

        for i, sg in enumerate(server_groups, 1):
            print(
                f"{i}. {sg['name']} (ID: {sg['id']}) - Used in {sg['count']} segments"
            )

        while True:
            try:
                choice = input(
                    f"\nSelect server group (1-{len(server_groups)}) or 'q' to cancel: "
                ).strip()
                if choice.lower() == "q":
                    return

                sg_index = int(choice) - 1
                if 0 <= sg_index < len(server_groups):
                    selected_sg = server_groups[sg_index]
                    break
                else:
                    print("Invalid selection. Please try again.")
            except ValueError:
                print("Invalid input. Please enter a number.")

        # Search for segments
        if has_matchstyle:
            print("\n📌 Note: matchStyle in API = 'Multimatch' toggle in ZPA UI")
            print("   - INCLUSIVE = Multimatch ON (matches ANY domain)")
            print("   - EXCLUSIVE = Multimatch OFF (more restrictive)")
            search_str = input(
                "\nEnter search string for segment names (or matchStyle:INCLUSIVE/EXCLUSIVE, or press Enter for all): "
            ).strip()
        else:
            search_str = input(
                "\nEnter search string for segment names (or press Enter for all): "
            ).strip()

        if search_str:
            if has_matchstyle:
                matching_segments = search_segments_with_matchstyle(
                    segments, search_str
                )
            else:
                matching_segments = search_segments_by_name(segments, search_str)
        else:
            matching_segments = segments

        if not matching_segments:
            print(f"\nNo segments found matching '{search_str}'")
            return

        print(f"\nFound {len(matching_segments)} segments")

        # Interactive selection
        selected_indices = set()
        current_index = 0

        while True:
            # Clear screen (simple version)
            print("\n" * 2)
            print("=" * 60)
            print(f"Server Group: {selected_sg['name']} (ID: {selected_sg['id']})")
            if search_str:
                print(f"Search: {search_str}")
            print("=" * 60)
            print()

            # Display segments
            for i, segment in enumerate(matching_segments):
                has_group = segment_has_server_group(segment, selected_sg["id"])
                selected = i in selected_indices

                prefix = ">" if i == current_index else " "
                checkbox = "[X]" if selected else "[ ]"

                # Build the display line
                name = segment.get("name", "Unknown")
                if has_matchstyle:
                    match_style = segment.get("matchStyle", "-")
                    if match_style != "-":
                        match_style = f"[{match_style[:3]}]"  # Show [INC] or [EXC]
                    else:
                        match_style = "[---]"
                    status = "[Has group: Yes]" if has_group else "[Has group: No]"
                    print(f"{prefix} {checkbox} {name:35} {match_style:5} {status}")
                else:
                    status = (
                        "[Has this group: Yes]" if has_group else "[Has this group: No]"
                    )
                    print(f"{prefix} {checkbox} {name:40} {status}")

            print(
                f"\nFound: {len(matching_segments)} segments ({len(selected_indices)} selected)"
            )
            print("\n[↑/↓] Navigate  [Space] Toggle  [a] Select All  [n] Select None")
            if has_matchstyle:
                print("[i] Select Inclusive  [e] Select Exclusive")
            print("[Enter] Continue  [q] Cancel")

            # Get single character input
            try:
                import sys

                # Platform-specific single char input
                if sys.platform == "win32":
                    import msvcrt

                    action = msvcrt.getch().decode("utf-8", errors="ignore")
                    # Windows arrow keys
                    if action == "\xe0":  # Special key prefix on Windows
                        action2 = msvcrt.getch().decode("utf-8", errors="ignore")
                        if action2 == "H":  # Up arrow
                            action = "UP"
                        elif action2 == "P":  # Down arrow
                            action = "DOWN"
                else:
                    # Unix/Linux/macOS
                    import tty, termios

                    fd = sys.stdin.fileno()
                    old_settings = termios.tcgetattr(fd)
                    try:
                        tty.setraw(sys.stdin.fileno())
                        ch = sys.stdin.read(1)
                        # Handle arrow keys (they send escape sequences)
                        if ch == "\x1b":  # ESC sequence
                            ch2 = sys.stdin.read(1)
                            ch3 = sys.stdin.read(1)
                            if ch2 == "[":
                                if ch3 == "A":  # Up arrow
                                    action = "UP"
                                elif ch3 == "B":  # Down arrow
                                    action = "DOWN"
                                else:
                                    action = ch
                            else:
                                action = ch
                        else:
                            action = ch
                    finally:
                        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
            except Exception:
                # Fallback to regular input if single char input fails
                action = input("\nAction: ").strip().lower()

            if action in ["q", "Q"]:
                return
            elif action in ["\r", "\n"]:  # Enter pressed
                if selected_indices:
                    break
                else:
                    print("\n\nNo segments selected. Please select at least one.")
                    input("Press Enter to continue...")
            elif action == " ":
                if current_index in selected_indices:
                    selected_indices.remove(current_index)
                else:
                    selected_indices.add(current_index)
            elif action in ["a", "A"]:
                selected_indices = set(range(len(matching_segments)))
            elif action in ["n", "N"]:
                selected_indices = set()
            elif action in ["i", "I"] and has_matchstyle:
                # Select all INCLUSIVE segments
                selected_indices = set(
                    i
                    for i, seg in enumerate(matching_segments)
                    if seg.get("matchStyle") == "INCLUSIVE"
                )
            elif action in ["e", "E"] and has_matchstyle:
                # Select all EXCLUSIVE segments
                selected_indices = set(
                    i
                    for i, seg in enumerate(matching_segments)
                    if seg.get("matchStyle") == "EXCLUSIVE"
                )
            elif action == "UP":  # up arrow
                current_index = max(0, current_index - 1)
            elif action == "DOWN":  # down arrow
                current_index = min(len(matching_segments) - 1, current_index + 1)

        # Choose operation
        print("\n" + "=" * 60)
        print("Select Operation:")
        print("=" * 60)
        print("a. Add server group to selected segments")
        print("r. Remove server group from selected segments")
        print("q. Cancel")

        while True:
            operation = input("\nChoice (a/r/q): ").strip().lower()
            if operation in ["a", "r", "q"]:
                break
            print("Invalid choice. Please enter 'a', 'r', or 'q'.")

        if operation == "q":
            return

        # Show summary and confirm
        print("\n" + "=" * 60)
        print("Summary of Changes:")
        print("=" * 60)

        changes_count = 0
        for i in selected_indices:
            segment = matching_segments[i]
            has_group = segment_has_server_group(segment, selected_sg["id"])

            if operation == "a" and not has_group:
                print(f"ADD to: {segment.get('name', 'Unknown')}")
                changes_count += 1
            elif operation == "r" and has_group:
                print(f"REMOVE from: {segment.get('name', 'Unknown')}")
                changes_count += 1

        if changes_count == 0:
            print(
                "No changes needed - selected segments already have the correct state."
            )
            input("\nPress Enter to continue...")
            return

        print(f"\nTotal changes: {changes_count}")

        confirm = input("\nApply these changes to local JSON? (y/n): ").strip().lower()
        if confirm != "y":
            print("Changes cancelled.")
            return

        # Apply changes
        for i in selected_indices:
            segment = matching_segments[i]

            # Find the segment in the original list
            for orig_segment in segments:
                if orig_segment["id"] == segment["id"]:
                    if operation == "a":
                        # Add server group if not present
                        if not segment_has_server_group(
                            orig_segment, selected_sg["id"]
                        ):
                            if "serverGroups" not in orig_segment:
                                orig_segment["serverGroups"] = []
                            orig_segment["serverGroups"].append(selected_sg["data"])
                    elif operation == "r":
                        # Remove server group if present
                        if "serverGroups" in orig_segment:
                            orig_segment["serverGroups"] = [
                                sg
                                for sg in orig_segment["serverGroups"]
                                if not (
                                    isinstance(sg, dict)
                                    and sg.get("id") == selected_sg["id"]
                                )
                            ]
                    break

        # Save changes
        with open(JSON_FILE, "w") as f:
            json.dump(data, f, indent=2)

        print(f"\n✓ Local JSON updated successfully!")
        print("⚠️  Remember to use 'Update' option to apply changes to ZPA")

    except Exception as e:
        logger.error(f"Error managing server groups: {e}")
        print(f"\nError: {e}")


def analyze_segments():
    """Analyze the local JSON file and display statistics"""
    try:
        data = load_local_segments()
        segments = data["segments"]

        # Calculate statistics
        total_segments = len(segments)

        # Count unique domain names
        all_domains = set()
        for segment in segments:
            domains = segment.get("domainNames", [])
            if domains:
                all_domains.update(domains)

        # Count unique server groups
        all_server_groups = set()
        for segment in segments:
            server_groups = segment.get("serverGroups", [])
            if server_groups:
                for sg in server_groups:
                    if isinstance(sg, dict) and "id" in sg:
                        all_server_groups.add(sg["id"])

        # Display analysis
        print("\n" + "=" * 60)
        print("Application Segments Analysis")
        print("=" * 60)
        print(f"\nFile: {JSON_FILE}")
        print(f"Downloaded: {data['metadata'].get('downloaded_at', 'Unknown')}")
        print(f"\nStatistics:")
        print(f"  • Total Application Segments: {total_segments}")
        print(f"  • Total Unique Domain Names: {len(all_domains)}")
        print(f"  • Total Server Groups Referenced: {len(all_server_groups)}")

        # Show top 5 segments by domain count
        segments_by_domain_count = sorted(
            segments, key=lambda x: len(x.get("domainNames", [])), reverse=True
        )[:5]

        if segments_by_domain_count:
            print(f"\nTop 5 Segments by Domain Count:")
            for seg in segments_by_domain_count:
                domain_count = len(seg.get("domainNames", []))
                if domain_count > 0:
                    print(f"  • {seg.get('name', 'Unknown')}: {domain_count} domains")

    except FileNotFoundError:
        print(f"\nError: {JSON_FILE} not found. Please download segments first.")
    except Exception as e:
        logger.error(f"Error analyzing segments: {e}")
        print(f"\nError analyzing segments: {e}")


def show_menu():
    """Display interactive menu and get user choice"""
    json_exists = os.path.exists(JSON_FILE)

    print("\n" + "=" * 60)
    print("ZPA Application Segment Editor")
    print("=" * 60)
    print("\nSelect an action:")
    print("1. Download application segments from ZPA")

    if json_exists:
        print("2. Preview differences (local vs ZPA)")
        print("3. Update application segments from local JSON")
        print("4. Analyze local application segments")
        print("5. Manage server groups in JSON")
        print("6. Exit")
    else:
        print("2. Exit")

    print("\n" + "-" * 60)

    while True:
        if json_exists:
            choice = input("\nEnter your choice (1-6): ").strip()
            if choice in ["1", "2", "3", "4", "5", "6"]:
                return choice
            print("Invalid choice. Please enter 1, 2, 3, 4, 5, or 6.")
        else:
            choice = input("\nEnter your choice (1-2): ").strip()
            if choice == "1":
                return "1"
            elif choice == "2":
                return "exit"
            print("Invalid choice. Please enter 1 or 2.")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="ZPA Application Segment Editor - Manage ZPA app segments via JSON"
    )
    parser.add_argument(
        "action",
        choices=["download", "update"],
        help="Action to perform",
        nargs="?",  # Makes the action optional
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")

    args = parser.parse_args()

    if args.debug:
        # In debug mode, enable debug logging to file only
        file_handler.setLevel(logging.DEBUG)
        logger.info("Debug mode enabled - verbose logging to file")

    try:
        # If no action provided, show interactive menu
        if args.action is None:
            while True:
                choice = show_menu()

                if choice == "1":
                    with ZPAClient() as client:  # Fresh client with proper cleanup
                        download_segments(client)
                    input("\nPress Enter to continue...")
                elif choice == "2":
                    if os.path.exists(JSON_FILE):
                        with ZPAClient() as client:  # Fresh client with proper cleanup
                            preview_diff(client)
                    else:
                        # This is the exit option when no JSON exists
                        print("Exiting...")
                        break
                    input("\nPress Enter to continue...")
                elif choice == "3":
                    with ZPAClient() as client:  # Fresh client with proper cleanup
                        update_segments(client, debug=args.debug)
                    input("\nPress Enter to continue...")
                elif choice == "4":
                    analyze_segments()
                    input("\nPress Enter to continue...")
                elif choice == "5":
                    manage_server_groups_local()
                    input("\nPress Enter to continue...")
                elif choice == "6" or choice == "exit":
                    print("Exiting...")
                    break
        else:
            # Use command line argument (no loop)
            with ZPAClient() as client:  # Fresh client with proper cleanup
                if args.action == "download":
                    download_segments(client)
                elif args.action == "update":
                    update_segments(client, debug=args.debug)

    except Exception as e:
        logger.error(f"Error: {e}")
        logger.debug(
            "Full exception details:", exc_info=True
        )  # Only log traceback in debug mode
        sys.exit(1)


if __name__ == "__main__":
    main()
