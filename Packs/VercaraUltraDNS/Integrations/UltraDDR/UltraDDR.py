import demistomock as demisto
from CommonServerPython import *
import urllib3
from typing import Any
from datetime import datetime, timedelta

urllib3.disable_warnings()


VENDOR = "vercara"
PRODUCT = "ultradns"
MAX_EVENTS_PER_FETCH = 10000
DEFAULT_GET_EVENTS_LIMIT = 50
DNS_LOG_ENDPOINT = "/dns-log-report/v3/logs"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
MARGIN_FETCH_OVERLAP_SECONDS = 3
MARGIN_DEDUP_SAFETY_SECONDS = 1


class Client(BaseClient):
    """UltraDDR API client with API key authentication and DNS log fetching."""

    def __init__(self, base_url: str, api_key: str, verify: bool = True, proxy: bool = False) -> None:
        """Initialize UltraDDR client with API key authentication support.

        Args:
            base_url: Base URL for UltraDDR API (e.g., https://api.ddr.ultradns.com)
            api_key: API key for authentication
            verify: Whether to verify SSL certificates (default: True)
            proxy: Whether to use proxy (default: False)
        """
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self.api_key = api_key

    def get_dns_logs(
        self,
        start_time: datetime,
        end_time: datetime | None = None,
        limit: int | None = None,
        page_token: str | None = None,
    ) -> dict[str, Any]:
        """Fetch DNS logs from UltraDDR API.

        Args:
            start_time: Start time for DNS log query (datetime object)
            end_time: End time for DNS log query (defaults to now if None)
            limit: Maximum number of records to fetch per page (optional)
            page_token: Pagination token for next page (optional)

        Returns:
            dict[str, Any]: API response with DNS logs

        Raises:
            DemistoException: If API request fails
        """
        if not end_time:
            end_time = datetime.now()

        start_time_str = start_time.strftime(DATE_FORMAT)
        end_time_str = end_time.strftime(DATE_FORMAT)

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }

        body: dict[str, Any] = {
            "startTime": start_time_str,
            "endTime": end_time_str
        }

        if limit:
            body["pageSize"] = limit

        if page_token:
            body["pageToken"] = page_token

        demisto.debug(f"Requesting DNS logs - Start: {start_time_str}, End: {end_time_str}, Limit: {limit}")

        response = self._http_request(
            method="POST",
            url_suffix=DNS_LOG_ENDPOINT,
            json_data=body,
            headers=headers,
            resp_type="response"
        )

        demisto.debug(f"API response status: {response.status_code}")

        try:
            json_response = response.json()
            events_count = len(json_response.get("logs", []))
            demisto.debug(f"Received {events_count} DNS log events from API")
        except ValueError as e:
            demisto.error(f"Failed to parse API response as JSON: {e}")
            raise DemistoException(f"Failed to parse JSON response: {e}")

        return json_response


def convert_time_string(time_str: str) -> datetime:
    """Convert API time string to datetime object.

    Args:
        time_str: Time string from API in ISO format

    Returns:
        datetime: Parsed datetime object

    Raises:
        DemistoException: If time string parsing fails
    """
    try:
        # Try parsing with microseconds
        return datetime.strptime(time_str, DATE_FORMAT)
    except ValueError:
        try:
            # Try parsing without microseconds
            return datetime.strptime(time_str, "%Y-%m-%dT%H:%M:%SZ")
        except ValueError as e:
            raise DemistoException(f"Failed to parse time string '{time_str}': {e}")


def _calculate_event_hash(event: dict[str, Any]) -> str:
    """Calculate hash of event for deduplication.

    Args:
        event: Event dictionary to hash

    Returns:
        str: SHA256 hash of the event content
    """
    import hashlib
    import json

    # Create a stable string representation of the event
    # Sort keys to ensure consistent hashing regardless of dict order
    event_str = json.dumps(event, sort_keys=True, default=str)
    return hashlib.sha256(event_str.encode()).hexdigest()


def _deduplicate_events(
    events: list[dict[str, Any]], event_cache: dict[str, str], upper_bound: datetime | None
) -> list[dict[str, Any]]:
    """Deduplicate events using hash-based comparison in boundary zone only.

    Args:
        events: List of processed events in chronological order (oldest first)
        event_cache: Cache of previous events {event_hash: timestamp_str}
        upper_bound: Only check duplicates for events <= this time (last_event_time + safety_margin)

    Returns:
        list[dict[str, Any]]: Deduplicated events (maintains original order)
    """
    if not events:
        return []

    filtered_events: list[dict[str, Any]] = []

    for event in events:
        # Parse event timestamp
        event_time_str = event.get("datetime", "")
        event_datetime = convert_time_string(event_time_str)

        # If event is newer than upper boundary, add all remaining events and break
        if upper_bound and event_datetime > upper_bound:
            demisto.debug(
                f"Event at {event_time_str} is beyond boundary, adding without duplicate check"
            )
            filtered_events.append(event)
            continue

        # Event is in boundary zone - check for duplicates
        event_hash = _calculate_event_hash(event)
        if event_hash in event_cache:
            demisto.debug(f"Duplicate detected - time: {event_time_str}, hash: {event_hash[:12]}..., dropping event")
            continue

        # Event is unique
        filtered_events.append(event)

    return filtered_events


def _cache_recent_events(events: list[dict[str, Any]], cache: dict[str, str], cutoff_time: datetime | None) -> None:
    """Cache recent events for future duplicate detection.

    Args:
        events: List of events in chronological order (oldest first)
        cache: Cache dictionary to update {event_hash: timestamp_str}
        cutoff_time: Only cache events newer or equal to this time
    """
    if not cutoff_time or not events:
        return

    for event in events:
        event_time_str = event.get("datetime", "")
        event_datetime = convert_time_string(event_time_str)

        if event_datetime < cutoff_time:
            continue  # Skip older events

        event_hash = _calculate_event_hash(event)
        cache[event_hash] = event_datetime.strftime("%Y-%m-%dT%H:%M:%S")


def _cleanup_event_cache(event_cache: dict[str, str], cutoff_time: datetime) -> dict[str, str]:
    """Clean up old event cache entries that are outside the retention window.

    Args:
        event_cache: Dictionary with event hash as key and ISO timestamp string as value
        cutoff_time: Time cutoff for retention (overlap + safety margin before latest event)

    Returns:
        dict[str, str]: Cleaned cache with only recent entries
    """
    cleaned_cache = {}
    removed_count = 0
    cutoff_time_str = cutoff_time.strftime("%Y-%m-%dT%H:%M:%S")

    for event_hash, timestamp_str in event_cache.items():
        try:
            if timestamp_str >= cutoff_time_str:
                cleaned_cache[event_hash] = timestamp_str
            else:
                removed_count += 1
        except Exception:
            # Keep entries with invalid timestamps to avoid data loss
            cleaned_cache[event_hash] = timestamp_str

    if removed_count > 0:
        demisto.debug(f"Cleaned {removed_count} old entries from event cache")

    return cleaned_cache


def process_events_for_xsiam(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Process events for XSIAM ingestion - adds _time, _vendor, _product, SOURCE_LOG_TYPE fields."""
    demisto.debug(f"Processing {len(events)} events for XSIAM ingestion")

    for event in events:
        datetime_obj = convert_time_string(event.get("datetime", ""))
        event["_time"] = datetime_obj.timestamp()
        event["_vendor"] = VENDOR
        event["_product"] = PRODUCT
        event["SOURCE_LOG_TYPE"] = "dns"
    return events


def test_module(client: Client, params: dict) -> str:
    """Test API connectivity and authentication.

    Args:
        client: UltraDDR client instance
        params: Integration parameters

    Returns:
        str: 'ok' if successful, error message if failed
    """
    demisto.debug("Starting test-module validation")

    # Validate max_events_per_fetch parameter in test-module
    #TODO reconsidre
    configured_limit = arg_to_number(params.get("max_events_per_fetch")) or MAX_EVENTS_PER_FETCH
    if configured_limit > MAX_EVENTS_PER_FETCH:
        raise DemistoException(
            f"The maximum number of DNS logs per fetch cannot exceed {MAX_EVENTS_PER_FETCH}. Configured: {configured_limit}"
        )
    try:
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=1)
        response = client.get_dns_logs(start_time=start_time, end_time=end_time, limit=1)

        if "logs" not in response:
            #TODO improve
            demisto.error("API test failed: Response missing logs field")
            return "API connectivity test failed: Invalid response format"

        event_count = len(response.get("logs", []))
        demisto.debug(f"API connectivity test successful, received {event_count} events")
        return "ok"

    except Exception as e:
        demisto.debug(f"Test failed: {e}")
        if "Forbidden" in str(e) or "Unauthorized" in str(e):
            return "Authentication Error: Please verify your API key"
        elif "timeout" in str(e).lower():
            return "Connection timeout: Please verify the server URL"
        else:
            return f"Connection failed: {str(e)}"


def get_events_command(client: Client, args: dict[str, Any]) -> tuple[list[dict], CommandResults]:
    """Manual command to fetch UltraDDR DNS log events.

    Args:
        client: UltraDDR client instance
        args: Command arguments dictionary containing limit, start_time, end_time, should_push_events

    Returns:
        tuple[list[dict], CommandResults]: Events list and CommandResults object

    Raises:
        DemistoException: If limit exceeds maximum or date parsing fails
    """
    #TODO do i need to validate this twice?
    demisto.debug(f"Executing get-events command with args: {args}")
    requested_limit = arg_to_number(args.get("limit")) or DEFAULT_GET_EVENTS_LIMIT
    if requested_limit > MAX_EVENTS_PER_FETCH:
        demisto.error(f"Requested limit {requested_limit} exceeds maximum {MAX_EVENTS_PER_FETCH}")
        raise DemistoException(f"Limit cannot exceed {MAX_EVENTS_PER_FETCH}. Requested: {requested_limit}")
    limit = requested_limit

    should_push_events = argToBoolean(args.get("should_push_events", False))

    start_time = dateparser.parse(args.get("start_time") or "")
    if not start_time:
        raise DemistoException(f"Invalid start_time format: {args.get('start_time')}")

    end_time_arg = args.get("end_time")
    if end_time_arg:
        end_time = dateparser.parse(end_time_arg)
        if not end_time:
            raise DemistoException(f"Invalid end_time format: {end_time_arg}")
    else:
        end_time = datetime.now()

    demisto.debug(f"Fetching events from {start_time} to {end_time}")

    all_events: list[dict[str, Any]] = []
    page_token = None
    page_count = 0

    while len(all_events) < limit:
        page_count += 1
        remaining_limit = limit - len(all_events)
        demisto.debug(f"Get-events page {page_count}, requesting {remaining_limit} events")

        response = client.get_dns_logs(start_time=start_time, end_time=end_time, limit=remaining_limit, page_token=page_token)
        page_events = response.get("logs", [])

        if not page_events:
            demisto.debug(f"No more events on page {page_count}, stopping")
            break

        all_events.extend(page_events)
        page_token = response.get("nextPageToken")

        if not page_token:
            demisto.debug(f"No more pages after page {page_count}")
            break

    events = all_events
    demisto.debug(f"Get-events retrieved a total of {len(events)} events across {page_count} pages")

    hr = tableToMarkdown(
        name="Vercara UltraDDR DNS Log Events",
        t=events,
        removeNull=True,
    )

    command_results = CommandResults(readable_output=hr, outputs_prefix="VercaraUltraDDR.DNSLogs", outputs=events)

    if should_push_events:
        processed_events = process_events_for_xsiam(events)
        send_events_to_xsiam(processed_events, vendor=VENDOR, product=PRODUCT)
        xsiam_msg = f"\n\nSuccessfully sent {len(processed_events)} events to XSIAM."
        command_results.readable_output = (command_results.readable_output or "") + xsiam_msg
        demisto.debug(f"Successfully pushed {len(processed_events)} events to XSIAM")
    else:
        demisto.debug("Events displayed only, not pushed to XSIAM")

    return events, command_results


def fetch_events(
    client: Client, last_run: dict[str, Any], max_events_per_fetch: int
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Fetch DNS log events with deduplication using hash-based approach.

    Args:
        client: UltraDDR client instance
        last_run: Previous run state containing last_fetch_time and event_cache
        max_events_per_fetch: Maximum number of events to fetch per cycle

    Returns:
        tuple[dict[str, Any], list[dict[str, Any]]]: Next run state and events

    Raises:
        Exception: If event fetching fails
    """
    demisto.debug(f"Starting fetch with last_run: {last_run}")
    last_fetch_time_str = last_run.get("last_fetch_time")
    event_cache = last_run.get("event_cache", {})

    # Determine fetch time window
    if last_fetch_time_str:
        last_event_time = datetime.fromisoformat(last_fetch_time_str)
        # Add overlap to ensure we don't miss any events
        start_time = last_event_time - timedelta(seconds=MARGIN_FETCH_OVERLAP_SECONDS)
        demisto.debug(
            f"Starting fetch from {last_event_time} with {MARGIN_FETCH_OVERLAP_SECONDS}s overlap, "
            f"{len(event_cache)} cached events"
        )
    else:
        last_event_time = None
        start_time = datetime.now() - timedelta(hours=3)
        demisto.debug("First fetch: collecting events from last 3 hours")

    end_time = datetime.now()

    # Initialize pagination variables
    raw_events: list[dict[str, Any]] = []
    page_token = None
    page_count = 0
    latest_event_time = last_event_time  # Will be updated with newest event from this fetch

    while len(raw_events) < max_events_per_fetch:
        page_count += 1
        remaining_limit = max_events_per_fetch - len(raw_events)

        response = client.get_dns_logs(start_time=start_time, end_time=end_time, limit=remaining_limit, page_token=page_token)

        events = response.get("logs", [])
        if not events:
            demisto.debug(f"No events returned on page {page_count}, stopping pagination")
            break

        demisto.debug(f"Page {page_count}: collected {len(events)} raw events")
        raw_events.extend(events)
        page_token = response.get("nextPageToken")
        if not page_token:
            break

    demisto.debug(f"Pagination complete: collected {len(raw_events)} total raw events from {page_count} pages")

    # Sort events by datetime (oldest first for processing)
    if raw_events:
        raw_events.sort(key=lambda x: x.get("datetime", ""))

    unique_events = []
    if raw_events:
        # Remove duplicates only in boundary zone where overlaps can occur
        duplication_upper_bound = (last_event_time + timedelta(seconds=MARGIN_DEDUP_SAFETY_SECONDS)) if last_event_time else None
        unique_events = _deduplicate_events(raw_events, event_cache, duplication_upper_bound)

    # Process unique events (update time, cache, and format for XSIAM)
    if unique_events:
        # Update latest event time (last event in sorted list)
        newest_event = unique_events[-1]
        latest_event_time = convert_time_string(newest_event.get("datetime", ""))
        demisto.debug(f"Latest event timestamp: {latest_event_time}")

        # Cache recent events and cleanup old cache entries using same cutoff
        cache_cutoff_time = latest_event_time - timedelta(seconds=MARGIN_FETCH_OVERLAP_SECONDS + MARGIN_DEDUP_SAFETY_SECONDS)
        _cache_recent_events(unique_events, event_cache, cache_cutoff_time)
        cleaned_cache = _cleanup_event_cache(event_cache, cache_cutoff_time)
        next_run_state = {"last_fetch_time": latest_event_time.strftime("%Y-%m-%dT%H:%M:%S"), "event_cache": cleaned_cache}

        unique_events = process_events_for_xsiam(unique_events)

        # Summary for events processed
        total_processed = len(raw_events)
        duplicates_filtered = total_processed - len(unique_events)
        demisto.debug(
            f"Fetch complete: {len(unique_events)} unique events from {total_processed} total "
            f"(filtered {duplicates_filtered} duplicates), next fetch from {latest_event_time}"
        )
    else:
        demisto.debug("No new events fetched, keeping last run unchanged")
        next_run_state = last_run

    return next_run_state, unique_events


def main() -> None:
    """Main entry point for UltraDDR integration.

    Returns:
        None

    Raises:
        Exception: If command execution fails, handled by return_error
    """

    params = demisto.params()
    command = demisto.command()
    args = demisto.args()

    base_url = params.get("url", "").rstrip("/")
    api_key = params.get("credentials", {}).get("password")
    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    # TODO when we know the limit will we enforce it?
    configured_limit = arg_to_number(params.get("max_events_per_fetch")) or MAX_EVENTS_PER_FETCH
    if configured_limit > MAX_EVENTS_PER_FETCH:
        demisto.info(
            f"Requested limit {configured_limit} exceeds maximum {MAX_EVENTS_PER_FETCH}. Using {MAX_EVENTS_PER_FETCH} instead."
        )
    max_events_per_fetch = min(configured_limit, MAX_EVENTS_PER_FETCH)

    try:
        client = Client(base_url=base_url, api_key=api_key, verify=verify_certificate, proxy=proxy)
        demisto.debug(f"Client initialized, executing command: {command}")

        if command == "test-module":
            result = test_module(client, params)
            return_results(result)

        elif command == "ultraddr-get-events":
            events, results = get_events_command(client, args)
            return_results(results)

        elif command == "fetch-events":
            last_run = demisto.getLastRun()
            next_run, events = fetch_events(client=client, last_run=last_run, max_events_per_fetch=max_events_per_fetch)

            if events:
                send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
                demisto.debug(f"Successfully sent {len(events)} events to XSIAM")
            else:
                demisto.debug("No events to send to XSIAM")

            demisto.setLastRun(next_run)
            demisto.debug(f"Fetch-events cycle completed successfully, set last run: {next_run}")

        else:
            raise NotImplementedError(f"Command {command} is not implemented.")

    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()