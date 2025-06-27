# ZPA JSON Application Segment Editor

A tool for managing Zscaler Private Access (ZPA) Application Segments through JSON configuration files. This utility enables bulk management, version control, and editing of ZPA application segments by synchronizing between the ZPA API and local JSON files.

---

**Copyright (c) 2025 ZHERO srl, Italy**  
**Website:** [https://zhero.ai](https://zhero.ai)

This project is released under the MIT License. See the LICENSE file for full details.

---

## Overview

This tool provides two main functions:

1. **Download**: Export all application segments from ZPA to a local JSON file
2. **Update**: Compare local JSON changes with ZPA and selectively apply updates

### Key Features

-   Full export of ZPA application segments to JSON format
-   Interactive diff viewer for reviewing changes before applying
-   Selective update capability - choose which changes to apply
-   Version control friendly - track configuration changes in Git
-   Bulk editing support through JSON manipulation
-   **Safety**: Deletions are not supported - segments cannot be accidentally deleted

## Installation

```bash
# Clone the repository
cd zpa-json-appsegment-editor

# Activate the conda environment
conda activate zscaler-api

# Install dependencies
pip install -r requirements.txt

# Set up environment configuration
cp .env.example .env
# Edit .env with your ZPA API credentials
```

## Configuration

Create a `.env` file with the following parameters:

```
CLIENT_ID=your_client_id_here
CLIENT_SECRET=your_client_secret_here
IDENTITY_BASE_URL=https://YOUR-DOMAIN.zsapi.net
CUSTOMER_ID=your_customer_id_here
```

Note: The IDENTITY_BASE_URL should be your organization's Zscaler identity domain (e.g., `https://mycompany.zsapi.net`)

## Usage

### Interactive Mode

Run without parameters to use the interactive menu:

```bash
python zpa_appsegment_editor.py
```

This will display a menu with options to:

-   Download application segments from ZPA
-   Preview differences (local vs ZPA) - shows a synthetic diff without making changes
-   Update application segments from local JSON (if JSON exists)
-   Analyze local application segments (if JSON exists)
-   Manage server groups in JSON (if JSON exists)
-   Exit

The menu loops after each action, allowing multiple operations in one session.

### Command Line Mode

#### Download Application Segments

Export all application segments from ZPA to a local JSON file:

```bash
python zpa_appsegment_editor.py download
```

This creates `application_segments.json` (gitignored by default).

#### Update Application Segments

Compare local JSON changes with ZPA and apply updates:

```bash
python zpa_appsegment_editor.py update
```

The update process:

1. Loads the local JSON file
2. Fetches current configuration from ZPA
3. Compares and identifies differences
4. Shows an interactive diff for each changed segment
5. Prompts for confirmation before applying each change:
    - `y` - Apply this change
    - `n` - Skip this change
    - `a` - Apply all remaining changes (requires double confirmation)
    - `q` - Quit without further changes

### Preview Differences

The preview feature (available in interactive mode) shows a synthetic diff between local JSON and ZPA:

-   **Summary statistics**: Total changes, additions, and modifications
-   **Added segments**: Segments that exist locally but not in ZPA
-   **Missing segments**: Segments that exist in ZPA but not locally (with warning that they won't be deleted)
-   **Modified segments**: Shows which fields have changed

This is useful for:

-   Reviewing changes before applying them
-   Understanding what will happen during an update
-   Verifying local edits before pushing to ZPA

**Important**: If segments are missing from your local JSON, they will NOT be deleted from ZPA. This tool only supports creating and updating segments, not deleting them.

### Analyze Segments

The analyze feature (available in interactive mode) provides statistics about your application segments:

-   Total number of application segments
-   Total unique domain names across all segments
-   Total server groups referenced
-   Top 5 segments by domain count

This helps understand the scope and complexity of your ZPA configuration.

### Manage Server Groups

The server group management feature (available in interactive mode) allows bulk operations on server groups:

1. **Select a server group** from existing groups in your segments
2. **Search for segments** by name (partial match, case-insensitive) or by matchStyle:
    - Regular search: `webapp` (finds segments with "webapp" in name)
    - Match style filter: `matchStyle:INCLUSIVE` or `matchStyle:EXCLUSIVE`
3. **Interactive selection** with keyboard navigation:
    - `↑/↓`: Move up/down (arrow keys)
    - `Space`: Toggle selection
    - `a`: Select all (immediate action)
    - `n`: Select none (immediate action)
    - `i`: Select all INCLUSIVE segments (only if matchStyle is present)
    - `e`: Select all EXCLUSIVE segments (only if matchStyle is present)
    - `Enter`: Continue with selected
4. **Choose operation**:
    - Add server group to selected segments
    - Remove server group from selected segments
5. **Review and confirm** changes before applying

**Match Style Display**: When segments have the `matchStyle` property, it will be shown as `[INC]` for INCLUSIVE or `[EXC]` for EXCLUSIVE in the segment list.

**Important**: This feature only modifies the local JSON file. Use the "Update" option to sync changes with ZPA.

### Example Workflow

```bash
# 1. Download current configuration
python zpa_appsegment_editor.py download

# 2. Edit application_segments.json with your preferred editor
# Make bulk changes like updating ports, protocols, or domains

# 3. Review and apply changes
python zpa_appsegment_editor.py update
```

## JSON Structure

The exported JSON contains an array of application segment objects:

```json
[
  {
    "id": "123456789",
    "name": "Internal Web App",
    "domainNames": ["app.internal.com"],
    "serverGroups": [...],
    "tcpPortRanges": ["443", "443"],
    "udpPortRanges": [],
    "matchStyle": "INCLUSIVE",
    ...
  }
]
```

### Understanding matchStyle (Multimatch)

The `matchStyle` property in the JSON corresponds to the **"Multimatch"** setting in the ZPA UI:

-   **`matchStyle: "INCLUSIVE"`** = **Multimatch ENABLED** in UI
-   **`matchStyle: "EXCLUSIVE"`** = **Multimatch DISABLED** in UI

**Note**: The API uses the term `matchStyle` while the ZPA UI shows this as the "Multimatch" toggle. They refer to the same functionality.

## API Endpoints Used

-   `GET /zpa/mgmtconfig/v1/admin/customers/{customerId}/application?pagesize=100` - List all application segments
-   `GET /zpa/mgmtconfig/v1/admin/customers/{customerId}/application/{id}` - Get specific segment details
-   `PUT /zpa/mgmtconfig/v1/admin/customers/{customerId}/application/{id}` - Update application segment

## Performance Notes

-   Handles pagination automatically for environments with 100+ application segments
-   Implements rate limiting to respect API quotas
-   Shows progress indicators for long-running operations

## Troubleshooting

### Common Issues

1. **Authentication Failed (400 Bad Request)**
    - Verify CLIENT_ID and CLIENT_SECRET in .env are correct
    - Check IDENTITY_BASE_URL format (should be like `https://yourcompany.zslogin.net`)
    - Ensure credentials are configured for OAuth 2.0 (not API key authentication)
    - Check the `zpa_editor.log` file for detailed error messages
2. **Authentication Failed (401 Unauthorized)**

    - Credentials may be expired or deactivated
    - Check if the OAuth app has appropriate permissions

3. **JSON Parse Error**

    - Validate JSON syntax using `python -m json.tool application_segments.json`
    - Ensure all required fields are present

4. **API Rate Limits**

    - The tool implements automatic retry with exponential backoff
    - For large environments, consider running during off-peak hours

5. **Segments Missing from Local JSON**
    - This is not an error - the tool will warn you but continue
    - Missing segments will NOT be deleted from ZPA
    - To delete segments, use the ZPA console directly

### Debug Mode

Enable verbose logging:

```bash
python zpa_appsegment_editor.py --debug download
```

All operations are logged to `zpa_editor.log` for troubleshooting. Check this file for detailed error messages and API responses.

## License

MIT License - See LICENSE file for details

## Contributing

When contributing to this project:

1. Follow the existing code style
2. Add appropriate error handling
3. Update this README for new features
4. Test with both small and large segment counts
