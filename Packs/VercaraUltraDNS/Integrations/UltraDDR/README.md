This integration fetches DNS log events from Vercara UltraDDR platform for security monitoring and threat detection.
This integration was integrated and tested with the Vercara UltraDDR API v3.#TODO fix the version

## Configure UltraDDR in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | The base URL for the Vercara UltraDDR API. Default is https://api.ddr.ultradns.com | True |
| API Key | API key for authentication | True |
| Trust any certificate (not secure) | Use SSL secure connection or not. | False |
| Use system proxy settings | Use proxy settings for connection or not. | False |
| Fetch events | Whether to bring events or not. | False |
| The maximum number of DNS logs per fetch | Maximum number of events to fetch per cycle. Default is 10,000, maximum is 10,000. #TODO fix this| False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### ultraddr-get-events

***
Gets DNS log events from Vercara UltraDDR. Manual command to fetch and display events. This command is used for developing/debugging and is to be used with caution, as it can create events, leading to events duplication and exceeding the API request limitation.

#### Base Command
#TODO rewrite this section
`ultraddr-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | If true, the command creates events; otherwise, it only displays them. Possible values are true and false. The default value is false. | Required |
| limit | Maximum number of events to return. Default is 50, maximum is 10,000. | Optional |
| start_time | Start time for event collection. Supports ISO format ("2023-01-01T00:00:00") or natural language ("7 days ago", "yesterday", "1 week ago"). | Required |
| end_time | End time for event collection. Supports ISO format ("2023-01-01T23:59:59") or natural language ("2 hours ago", "now"). Default is now if not provided. | Optional |

#### Context Output

There is no context output for this command.

For detailed API documentation, see the [UltraDDR API Documentation](https://api.ddr.ultradns.com/docs/ultraddr/).
