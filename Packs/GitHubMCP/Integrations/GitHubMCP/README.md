Use this integration to connect securely with a GitHub Model Context Protocol (MCP) server and access its tools in real time.
This integration was integrated and tested with version xx of GitHubMCP.

## Configure GitHub MCP in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Personal Access Token | GitHub Personal Access Token | True |
| Enabled Toolsets | If no toolsets are selected, GitHub's default toolsets 'context', 'repos', 'issues', 'pull_requests', and 'users' will be enabled. |  |
| Enable Read-Only Tools |  |  |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### list-tools

***
Retrieves a list of available tools in the GitHub MCP server.

#### Base Command

`list-tools`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ListTools.Tools.name | String | The name of the available tool in the MCP server. | 
| ListTools.Tools.description | String | Description of the available tool in the MCP server | 
| ListTools.Tools.inputSchema.type | String | Input schema type for the tool in the MCP server | 
| ListTools.Tools.inputSchema.properties | String | Detailed properties of the tool's input schema | 
| ListTools.Tools.inputSchema.required | String | Required input fields for the tool | 

### call-tool

***
Calls a specific tool on the GitHub MCP server with optional input parameters.

#### Base Command

`call-tool`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the tool to call. | Required | 
| arguments | Parameters for the tool execution. | Optional | 

#### Context Output

There is no context output for this command.
