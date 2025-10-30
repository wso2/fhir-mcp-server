# Model Context Protocol (MCP) Server for Fast Healthcare Interoperability Resources (FHIR) APIs

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/wso2/fhir-mcp-server/blob/main/LICENSE)
[![Get Support on Stack Overflow](https://img.shields.io/badge/stackoverflow-wso2-orange)](https://stackoverflow.com/questions/tagged/wso2)
[![Join the community on Discord](https://img.shields.io/badge/Join%20us%20on-Discord-%23e01563.svg)](https://discord.com/invite/wso2)
[![X](https://img.shields.io/twitter/follow/wso2.svg?style=social&label=Follow)](https://twitter.com/intent/follow?screen_name=wso2)

## Table of Contents
- [Model Context Protocol (MCP) Server for Fast Healthcare Interoperability Resources (FHIR) APIs](#model-context-protocol-mcp-server-for-fast-healthcare-interoperability-resources-fhir-apis)
  - [Table of Contents](#table-of-contents)
  - [Overview](#overview)
  - [Demo](#demo)
    - [Demo with HAPI FHIR server](#demo-with-hapi-fhir-server)
    - [Demo with EPIC Sandbox](#demo-with-epic-sandbox)
  - [Core Features](#core-features)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
    - [Installing using PyPI Package](#installing-using-pypi-package)
    - [Installing from Source](#installing-from-source)
    - [Installing using Docker](#installing-using-docker)
        - [Running the MCP Server with Docker](#running-the-mcp-server-with-docker)
        - [Using Docker Compose with HAPI FHIR Server](#using-docker-compose-with-hapi-fhir-server)
  - [Integration with MCP Clients](#integration-with-mcp-clients)
    - [VS Code](#vs-code)
    - [Claude Desktop](#claude-desktop)
    - [MCP Inspector](#mcp-inspector)
  - [Configuration](#configuration)
    - [CLI Options](#cli-options)
    - [Environment Variables](#environment-variables)
  - [Tools](#tools)
  - [Development \& Testing](#development--testing)
    - [Installing Development Dependencies](#installing-development-dependencies)
    - [Running Tests](#running-tests)


## Overview

The FHIR MCP Server is a Model Context Protocol (MCP) server that provides seamless integration with FHIR APIs. Designed for developers, integrators, and healthcare innovators, this server acts as a bridge between modern AI/LLM tools and healthcare data, making it easy to search, retrieve, and analyze clinical information.

## Demo

### Demo with HAPI FHIR server

This video showcases the MCP server's functionality when connected to a public [HAPI FHIR server](https://hapi.fhir.org/). This example showcases direct interaction with an open FHIR server that does not require an authorization flow.

https://github.com/user-attachments/assets/cc6ac87e-8329-4da4-a090-2d76564a3abf

### Demo with EPIC Sandbox

This video showcases the MCP server's capabilities within the [Epic EHR ecosystem](https://open.epic.com/). It demonstrates the complete OAuth 2.0 Authorization Code Grant flow.

https://github.com/user-attachments/assets/96b433f1-3e53-4564-8466-65ab48d521de

## Core Features

- **MCP-compatible transport**: Serves FHIR via stdio, SSE, or streamable HTTP

- **SMART-on-FHIR based authentication support**: Securely authenticate with FHIR servers and clients

- **Tool integration**: Integratable with any MCP client such as VS Code, Claude Desktop, and MCP Inspector

## Prerequisites

- Python 3.8+
- [uv](https://github.com/astral-sh/uv) (for dependency management)
- An accessible FHIR API server.

## Installation

You can use the FHIR MCP Server by installing our Python package, or by cloning this repository.

### Installing using PyPI Package

1. **Configure Environment Variables:**
    
    To run the server, you must set `FHIR_SERVER_BASE_URL`.

    * **To enable authorization:** Set `FHIR_SERVER_BASE_URL`, `FHIR_SERVER_CLIENT_ID`, `FHIR_SERVER_CLIENT_SECRET`, and `FHIR_SERVER_SCOPES`. Authorization is enabled by default.
    * **To disable authorization:** Set `FHIR_SERVER_DISABLE_AUTHORIZATION` to `True`.

    By default, the MCP server runs on **[http://localhost:8000](http://localhost:8000)**, and you can customize the host and port using `FHIR_MCP_HOST` and `FHIR_MCP_PORT`.


    You can set these by exporting them as environment variables like below or by creating a `.env` file (referencing `.env.example`).

    ```bash 
    export FHIR_SERVER_BASE_URL=""
    export FHIR_SERVER_CLIENT_ID=""
    export FHIR_SERVER_CLIENT_SECRET=""
    export FHIR_SERVER_SCOPES=""

    export FHIR_MCP_HOST="localhost"
    export FHIR_MCP_PORT="8000"
    ```

2. **Install the PyPI package and run the server**

    ```bash
    uvx fhir-mcp-server
    ```

### Installing from Source

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

4. **Run the server:**
    ```bash
    uv run fhir-mcp-server
    ```

### Installing using Docker

#### Running the MCP Server with Docker

You can run the MCP server using Docker for a consistent, isolated environment. 

>Note on **Authorization**: When running the MCP server **locally** via Docker or Docker Compose, authorization should be disabled by setting the environment variable, `FHIR_SERVER_DISABLE_AUTHORIZATION=True` . This would be fixed in the future releases.

1. Build the Docker Image or pull the docker image from the container registry:

    * Build from source:
        ```bash
        docker build -t fhir-mcp-server .
        ```
    * Pull from GitHub Container Registry:
        ```bash
        docker pull wso2/fhir-mcp-server:latest
        ```

2. Configure Environment Variables

    Copy the example environment file and edit as needed:

    ```bash
    cp .env.example .env
    # Edit .env to set your FHIR server, client credentials, etc.
    ```

    Alternatively, you can pass environment variables directly with `-e` flags or use Docker secrets for sensitive values. See the [Configuration](#configuration) section for details on available environment variables.

3. Run the Container

    ```bash
    docker run --env-file .env -p 8000:8000 fhir-mcp-server
    ```

    This will start the server and expose it on port 8000. Adjust the port mapping as needed.

#### Using Docker Compose with HAPI FHIR Server

For a quick setup that includes both the FHIR MCP server and a HAPI FHIR server (with PostgreSQL), use the provided `docker-compose.yml`. This sets up an instant development environment for testing FHIR operations.

1. **Prerequisites:**
   - Docker and Docker Compose installed.

2. **Run the Stack:**

   ```bash
   docker-compose up -d
   ```

   This command will:
   - Start a PostgreSQL database container.
   - Launch the HAPI FHIR server (connected to PostgreSQL) listening on http://localhost:8080.
   - Build and run the FHIR MCP server container listening on http://localhost:8000, with `FHIR_SERVER_BASE_URL` set to http://hapi-r4-postgresql:8080/fhir.

3. **Access the Services:**
   - FHIR MCP Server: http://localhost:8000
   - HAPI FHIR Server: http://localhost:8080
   - To stop run `docker-compose down`.

4. **Configure Additional Environment Variables:**

   If you need to customize OAuth or other settings, adjust the env variables in the `docker-compose.yml`. The compose file sets basic configuration; refer to the [Configuration](#configuration) section for full options.

## Integration with MCP Clients

The FHIR MCP Server is designed for seamless integration with various MCP clients.

### VS Code

[![Install in VS Code](https://img.shields.io/badge/VS_Code-Install_Server-0098FF?style=flat-square&logo=visualstudiocode&logoColor=white)](https://insiders.vscode.dev/redirect/mcp/install?name=fhir&config=%7B%22type%22%3A%22http%22%2C%22url%22%3A%22http%3A%2F%2Flocalhost%3A8000%2Fmcp%2F%22%7D)
[![Install in VS Code Insiders](https://img.shields.io/badge/VS_Code_Insiders-Install_Server-24bfa5?style=flat-square&logo=visualstudiocode&logoColor=white)](https://insiders.vscode.dev/redirect/mcp/install?name=fhir&config=%7B%22type%22%3A%22http%22%2C%22url%22%3A%22http%3A%2F%2Flocalhost%3A8000%2Fmcp%2F%22%7D)

Add the following JSON block to your User Settings (JSON) file in VS Code (> V1.101). You can do this by pressing Ctrl + Shift + P and typing Preferences: Open User Settings (JSON).

<table>
<tr><th>Streamable HTTP</th><th>STDIO</th><th>SSE</th></tr>
<tr valign=top>
<td>

```json
"mcp": {
    "servers": {
        "fhir": {
            "type": "http",
            "url": "http://localhost:8000/mcp",
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
                "FHIR_SERVER_ACCESS_TOKEN": "Your FHIR Access Token"
            }
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
            "type": "sse",
            "url": "http://localhost:8000/sse",
        }
    }
}
```
</td>
</tr>
</table>

### Claude Desktop
Add the following JSON block to your Claude Desktop settings to connect to your local MCP server. 
 - Launch the Claude Desktop app, click on the Claude menu in the top bar, and select "Settings…".
 - In the Settings pane, click “Developer” in the left sidebar. Then click "Edit Config". This will open your configuration file in your file system. If it doesn’t exist yet, Claude will create one automatically at:
    - macOS: ~/Library/Application Support/Claude/claude_desktop_config.json
    - Windows: %APPDATA%\Claude\claude_desktop_config.json
 - Open the claude_desktop_config.json file in any text editor. Replace its contents with the following JSON block to register the MCP server:

<table>
<tr><th>Streamable HTTP</th><th>STDIO</th><th>SSE</th></tr>
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
                "FHIR_SERVER_ACCESS_TOKEN": "Your FHIR Access Token"
            }
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
            "command": "npx",
            "args": [
                "-y",
                "mcp-remote",
                "http://localhost:8000/sse"
            ]
        }
    }
}
```
</td>
</tr>
</table>

### MCP Inspector
Follow these steps to get the MCP Inspector up and running:

- Open a terminal and run the following command:
    
    `npx -y @modelcontextprotocol/inspector`

- In the MCP Inspector interface:
<table>
<tr><th>Streamable HTTP</th><th>STDIO</th><th>SSE</th></tr>
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

<td>

- Transport Type: `SSE`
- URL: `http://localhost:8000/sse`
</td>
</tr>
</table>

Make sure your MCP server is already running and listening on the above endpoint.

Once connected, MCP Inspector will allow you to visualize tool invocations, inspect request/response payloads, and debug your tool implementations easily.

## Configuration

### CLI Options

You can customize the behavior of the MCP server using the following command-line flags:

- **--transport**
    - Description: Specifies the transport protocol used by the MCP server to communicate with clients.
    - Accepted values: stdio, sse, streamable-http
    - Default: streamable-http

- **--log-level**
    - Description: Sets the logging verbosity level for the server.
    - Accepted values: DEBUG, INFO, WARN, ERROR (case-insensitive)
    - Default: INFO

- **--help**
    - Description: Displays a help message with available server options and exits.
    - Usage: Automatically provided by the command-line interface.

Sample Usages:

```shell
uv run fhir-mcp-server --transport streamable-http --log-level DEBUG
uv run fhir-mcp-server --help
```

### Environment Variables

**MCP Server Configurations:**
- `FHIR_MCP_HOST`: The hostname or IP address the MCP server should bind to (e.g., `localhost` for local-only access, or `0.0.0.0` for all interfaces).
- `FHIR_MCP_PORT`: The port on which the MCP server will listen for incoming client requests (e.g., `8000`).
- `FHIR_MCP_SERVER_URL`: If set, this value will be used as the server's base URL instead of generating it from host and port. Useful for custom URL configurations or when behind a proxy.
- `FHIR_MCP_REQUEST_TIMEOUT`: Timeout duration in seconds for requests from the MCP server to the FHIR server (default: `30`).

**MCP Server OAuth2 with FHIR server Configuration (MCP Client ↔ MCP Server):**
These variables configure the MCP client's secure connection to the MCP server, using the OAuth2 authorization code grant flow with a FHIR server.

- `FHIR_SERVER_CLIENT_ID`: The OAuth2 client ID used to authorize MCP clients with the FHIR server.
- `FHIR_SERVER_DISABLE_AUTHORIZATION`: If set to `True`, disables authorization checks on the MCP server, allowing connections to publicly accessible FHIR servers.
- `FHIR_SERVER_CLIENT_SECRET`: The client secret corresponding to the FHIR client ID. Used during token exchange.
- `FHIR_SERVER_BASE_URL`: The base URL of the FHIR server (e.g., `https://hapi.fhir.org/baseR4`). This is used to generate tool URIs and to route FHIR requests.
- `FHIR_SERVER_SCOPES`: A space-separated list of OAuth2 scopes to request from the FHIR authorization server (e.g., `user/Patient.read user/Observation.read`). Add `fhirUser openid` to enable retrieval of user context for the `get_user` tool. If these two scopes are not configured, the `get_user` tool returns an empty result because the ID token lacks the user's FHIR resource reference.
- `FHIR_SERVER_ACCESS_TOKEN`: The access token to use for authenticating requests to the FHIR server. If this variable is set, the server will bypass the OAuth2 authorization flow and use this token directly for all requests.

## Tools

- `get_capabilities`: Retrieves metadata about a specified FHIR resource type, including its supported search parameters and custom operations.
    - `type`: The FHIR resource type name (e.g., "Patient", "Observation", "Encounter")

- `search`: Executes a standard FHIR search interaction on a given resource type, returning a bundle or list of matching resources.
    - `type`: The FHIR resource type name (e.g., "MedicationRequest", "Condition", "Procedure").
    - `searchParam`: A mapping of FHIR search parameter names to their desired values (e.g., {"family":"Simpson","birthdate":"1956-05-12"}).

- `read`: Performs a FHIR "read" interaction to retrieve a single resource instance by its type and resource ID, optionally refining the response with search parameters or custom operations.
    - `type`: The FHIR resource type name (e.g., "DiagnosticReport", "AllergyIntolerance", "Immunization").
    - `id`: The logical ID of a specific FHIR resource instance.
    - `searchParam`: A mapping of FHIR search parameter names to their desired values (e.g., {"device-name":"glucometer"}).
    - `operation`: The name of a custom FHIR operation or extended query defined for the resource (e.g., "$everything").

- `create`: Executes a FHIR "create" interaction to persist a new resource of the specified type.
    - `type`: The FHIR resource type name (e.g., "Device", "CarePlan", "Goal").
    - `payload`: A JSON object representing the full FHIR resource body to be created.
    - `searchParam`: A mapping of FHIR search parameter names to their desired values (e.g., {"address-city":"Boston"}).
    - `operation`: The name of a custom FHIR operation or extended query defined for the resource (e.g., "$evaluate").

- `update`: Performs a FHIR "update" interaction by replacing an existing resource instance's content with the provided payload.
    - `type`: The FHIR resource type name (e.g., "Location", "Organization", "Coverage").
    - `id`: The logical ID of a specific FHIR resource instance.
    - `payload`: The complete JSON representation of the FHIR resource, containing all required elements and any optional data.
    - `searchParam`: A mapping of FHIR search parameter names to their desired values (e.g., {"patient":"Patient/54321","relationship":"father"}).
    - `operation`: The name of a custom FHIR operation or extended query defined for the resource (e.g., "$lastn").

- `delete`: Execute a FHIR "delete" interaction on a specific resource instance.
    - `type`: The FHIR resource type name (e.g., "ServiceRequest", "Appointment", "HealthcareService").
    - `id`: The logical ID of a specific FHIR resource instance.
    - `searchParam`: A mapping of FHIR search parameter names to their desired values (e.g., {"category":"laboratory","issued:"2025-05-01"}).
    - `operation`: The name of a custom FHIR operation or extended query defined for the resource (e.g., "$expand").

- `get_user`: Retrieves the currently authenticated user's FHIR resource (for example the linked `Patient` resource) and returns a concise profile containing available demographic fields such as `id`, `name`, and `birthDate`.

## Development & Testing

### Installing Development Dependencies

To run tests and contribute to development, install the test dependencies:

**Using pip:**
```bash
# Install project in development mode with test dependencies
pip install -e '.[test]'

# Or install from requirements file
pip install -r requirements-dev.txt
```

**Using uv:**
```bash
# Install development dependencies
uv sync --dev
```

### Running Tests

The project includes a comprehensive test suite covering all major functionality:

```bash
# Simple test runner
python run_tests.py

# Or direct pytest usage
PYTHONPATH=src python -m pytest tests/ -v --cov=src/fhir_mcp_server
```
**Using pytest:**
```bash
pytest tests/
```
This will discover and run all tests in the `tests/` directory.


**Test Features:**
- **100+ tests** with comprehensive coverage
- **Full async/await support** using pytest-asyncio
- **Complete mocking** of HTTP requests and external dependencies
- **Coverage reporting** with terminal and HTML output
- **Fast execution** with no real network calls

The test suite includes:
- **Unit tests**: Core functionality testing
- **Integration tests**: Component interaction validation
- **Edge case coverage**: Error handling and validation scenarios
- **Mocked OAuth flows**: Realistic authentication testing

Coverage reports are generated in `htmlcov/index.html` for detailed analysis.

<!-- mcp-name: io.github.wso2/fhir-mcp-server -->
