# Model Context Protocol (MCP) Server for Fast Healthcare Interoperability Resources (FHIR)

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/wso2/fhir-mcp-server/blob/main/LICENSE)
[![Get Support on Stack Overflow](https://img.shields.io/badge/stackoverflow-wso2-orange)](https://stackoverflow.com/questions/tagged/wso2)
[![Join the community on Discord](https://img.shields.io/badge/Join%20us%20on-Discord-%23e01563.svg)](https://discord.com/invite/wso2)
[![X](https://img.shields.io/twitter/follow/wso2.svg?style=social&label=Follow)](https://twitter.com/intent/follow?screen_name=wso2)

## Overview

The MCP Server for FHIR is a Python-based service that provides seamless, standardized access to FHIR data from any compatible FHIR server. Designed for developers, integrators, and healthcare innovators, this server acts as a bridge between modern AI/LLM tools and healthcare data, making it easy to search, retrieve, and analyze clinical information.

**Key features:**
- **Flexible Integration:** Use the server from the command line, in Docker, or directly within tools like VS Code, Claude Desktop, and MCP Inspector.
- **Natural Language FHIR Search:** Query for patients, allergies, immunizations, care plans, and more using simple prompts or programmatic requests.
- **Configurable & Secure:** Easily connect to any FHIR server, with support for environment-based configuration and secure access tokens.
- **Developer Friendly:** Quick setup with modern Python tooling (`uv`), clear documentation, and ready-to-use integration examples for rapid prototyping and deployment.

Whether you are building healthcare applications, integrating with AI assistants, or exploring clinical datasets, the MCP server provides a robust foundation for accessing and working with FHIR data in a standardized, extensible way.

## Prerequisites
- Python 3.8+
- [uv](https://github.com/astral-sh/uv) (for dependency management)
- An accessible FHIR server (defaults to the public HAPI FHIR test server)

## Setup

1. **Clone the repository:**
    ```bash
    git clone <repository_url>
    cd <repository_directory>
    ```
2. **Create a virtual environment and install dependencies:**
    ```bash
    uv venv
    source .venv/bin/activate
    uv pip sync requirements.txt
    ```
    Or with pip:
    ```bash
    python -m venv .venv
    source .venv/bin/activate
    pip install -r requirements.txt
    ```
3. **Configure Environment Variables:**
    Copy the example file and customize if needed:
    ```bash
    cp .env.example .env
    ```

## Usage

Run the server:
```bash
uv run fhir-mcp-server
```

You can also run the server directly from the PyPI package (without cloning the repository) using:

```bash
uvx fhir-mcp-server
```

## VS Code Integration
Add the following JSON block to your User Settings (JSON) file in VS Code. You can do this by pressing Ctrl + Shift + P and typing Preferences: Open User Settings (JSON).

<table>
<tr><th>Streamable HTTP</th><th>stdio</th></tr>
<tr valign=top>
<td>

```json
"mcp": {
    "servers": {
        "fhir": {
            "command": "npx",
            "args": [
                "-y",
                "mcp-remote",
                "http://localhost:8000/mcp"
            ]
        }
    }
}
```
</td>
<td>

```json
"mcp": {
    "servers": {
        "fhir": {
            "command": "uv",
            "args": [
                "--directory",
                "/path/to/fhir-mcp-server",
                "run",
                "fhir-mcp-server",
                "--transport",
                "stdio"
            ],
            "env": {
                "HEALTHCARE_MCP_FHIR__ACCESS_TOKEN": "Your FHIR Access Token"
            }
        }
    }
}
```
</td>
</tr>
</table>

## Claude Desktop Integration
Add the following JSON block to your Claude Desktop settings to connect to your local MCP server. 
 - Launch the Claude Desktop app, click on the Claude menu in the top bar, and select "Settings…".
 - In the Settings pane, click “Developer” in the left sidebar. Then click "Edit Config". This will open your configuration file in your file system. If it doesn’t exist yet, Claude will create one automatically at:
    - macOS: ~/Library/Application Support/Claude/claude_desktop_config.json
    - Windows: %APPDATA%\Claude\claude_desktop_config.json
 - Open the claude_desktop_config.json file in any text editor. Replace its contents with the following JSON block to register the MCP server:

<table>
<tr><th>Streamable HTTP</th><th>stdio</th></tr>
<tr valign=top>
<td>

```json
{
    "mcpServers": {
        "fhir": {
            "command": "npx",
            "args": [
                "-y",
                "mcp-remote",
                "http://localhost:8000/mcp"
            ]
        }
    }
}
```
</td>
<td>

```json
{
    "mcpServers": {
        "fhir": {
            "command": "uv",
            "args": [
                "--directory",
                "/path/to/fhir-mcp-server",
                "run",
                "fhir-mcp-server",
                "--transport",
                "stdio"
            ],
            "env": {
                "HEALTHCARE_MCP_FHIR__ACCESS_TOKEN": "Your FHIR Access Token"
            }
        }
    }
}
```
</td>
</tr>
</table>

## MCP Inspector Integration
Follow these steps to get the MCP Inspector up and running:

- Open a terminal and run the following command:
    
    `npx -y @modelcontextprotocol/inspector`

- In the MCP Inspector interface:
<table>
<tr><th>Streamable HTTP</th><th>stdio</th></tr>
<tr valign=top>
<td>

- Transport Type: `Streamable HTTP`
- URL: `http://localhost:8000/mcp`
</td>
<td>

- Transport Type: `STDIO`
- Command: `uv`
- Arguments: `--directory /path/to/fhir-mcp-server run fhir-mcp-server --transport stdio`
</td>
</tr>
</table>

Make sure your MCP server is already running and listening on the above endpoint.

Once connected, MCP Inspector will allow you to visualize tool invocations, inspect request/response payloads, and debug your tool implementations easily.

## Example Prompts
- Get allergy history for patient 53373
- Fetch the immunization records for patient ID 53373
- List all active care plans for patient 22
- Provide a consolidated report for patient 53373 that includes their complete allergy history as well as all available immunization records, organized by date and highlighting any critical alerts
- Retrieve all active care plans for patient ID 22 and present them in a markdown table showing each plan’s ID, title, status, intent, and start date
