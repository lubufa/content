from CommonServerPython import *  # noqa: F401
import demistomock as demisto  # noqa: F401

""" CONSTANTS """

VENDOR = "CreateAlerts"
PRODUCT = "CreateAlerts"


""" MAIN FUNCTION """

def main() -> None:  # pragma: no cover
    try:
        params = demisto.params()
        command = demisto.command()
        args = demisto.args()

        demisto.debug(f"Command being called is {command}")
        client = Client(
            base_url=params.get("url"), use_ssl=not params.get("insecure", True), use_proxy=params.get("proxy", False)
        )
        if command == "fetch-events":
            send_events_to_xsiam(
                [
                    {
                        "_time": datetime.now().isoformat(),
                        "actorId": "1234567890",
                        "actorName": "John Doe",
                        "type": "audit",
                    }
                ],
                VENDOR,
                PRODUCT
            )

        elif command == "test-module":
            return_results("ok")

        # elif command == "create-test-incident-from-file":
        #     ...

        # elif command == "create-test-incident-from-raw-json":
        #     ...

    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {demisto.command()} command.\nError:\n{e!s}, {traceback.format_exc()}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
