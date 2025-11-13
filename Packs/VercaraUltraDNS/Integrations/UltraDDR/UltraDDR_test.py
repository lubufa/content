import pytest
import requests_mock
from freezegun import freeze_time
from datetime import datetime
import json
from unittest.mock import patch
from CommonServerPython import *

from UltraDDR import (
    Client,
    convert_time_string,
    _calculate_event_hash,
    _deduplicate_events,
    _cache_recent_events,
    _cleanup_event_cache,
    process_events_for_xsiam,
    fetch_events,
    get_events_command,
    VENDOR,
    PRODUCT,
)

BASE_URL = "https://api.ddr.ultradns.com"
API_KEY = "test_api_key_12345"
DNS_LOG_URL = f"{BASE_URL}/dns-log-report/v3/logs"


def util_load_json(path):
    """Load JSON data from test_data directory."""
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


def mock_send_events_to_xsiam(events, vendor, product):
    """Mock function for send_events_to_xsiam."""
    return events, vendor, product


@pytest.fixture
def client() -> Client:
    """
    Fixture to create and return a Client instance for testing.
    Uses mock credentials defined at the top of the file.
    """
    return Client(base_url=BASE_URL, api_key=API_KEY, verify=True, proxy=False)


class TestClient:
    """Test cases for Client class."""

    def test_client_init(self):
        """
        Given:
        - Valid UltraDDR API key and base URL

        When:
        - Creating a new Client instance

        Then:
        - Client should be initialized with correct parameters
        - API key should be stored correctly
        """
        client = Client(base_url=BASE_URL, api_key=API_KEY, verify=True, proxy=False)

        assert client._base_url == BASE_URL
        assert client.api_key == API_KEY

    def test_get_dns_logs_success(self):
        """
        Given:
        - Authenticated client with valid API key
        - Mock DNS logs endpoint returning events
        - Valid time range parameters

        When:
        - Calling get_dns_logs method

        Then:
        - Should return DNS log events from API
        - Should include pagination token if available
        """
        dns_response = util_load_json("test_data/dns_logs.json")

        with requests_mock.Mocker() as mocker:
            mocker.post(DNS_LOG_URL, json=dns_response)

            client = Client(BASE_URL, API_KEY)
            start_time = datetime(2025, 9, 27, 14, 0, 0)
            end_time = datetime(2025, 9, 27, 15, 0, 0)

            result = client.get_dns_logs(start_time=start_time, end_time=end_time, limit=100)

            assert "logs" in result
            assert len(result["logs"]) == 3
            assert result.get("nextPageToken") == "token_abc123"

    def test_get_dns_logs_authentication_failure(self):
        """
        Given:
        - Invalid API key
        - Mock DNS logs endpoint returning 401 error

        When:
        - Calling get_dns_logs method

        Then:
        - Should raise DemistoException with authentication error
        """
        with requests_mock.Mocker() as mocker:
            mocker.post(DNS_LOG_URL, status_code=401, json={"error": "invalid_api_key"})

            client = Client(BASE_URL, API_KEY)
            start_time = datetime(2025, 9, 27, 14, 0, 0)
            end_time = datetime(2025, 9, 27, 15, 0, 0)

            with pytest.raises(DemistoException):
                client.get_dns_logs(start_time=start_time, end_time=end_time)


class TestUtilityFunctions:
    @pytest.mark.parametrize(
        "time_str,expected",
        [
            ("2025-09-27T14:30:00.123456Z", datetime(2025, 9, 27, 14, 30, 0, 123456)),
            ("2025-09-27T14:30:00Z", datetime(2025, 9, 27, 14, 30, 0)),
        ],
    )
    def test_convert_time_string_success(self, time_str, expected):
        """
        Given:
        - Valid API time string in expected format (with or without microseconds)

        When:
        - Converting time string to datetime object

        Then:
        - Should return correct timezone-naive datetime object
        """
        result = convert_time_string(time_str)

        assert isinstance(result, datetime)
        assert result.tzinfo is None  # Should be timezone-naive
        assert result == expected

    def test_convert_time_string_invalid(self):
        """
        Given:
        - Invalid time string that cannot be parsed

        When:
        - Converting time string to datetime object

        Then:
        - Should raise DemistoException with detailed parsing error
        """
        invalid_time = "2025-09-27 14:30:00"  # Wrong format (missing T and Z)

        with pytest.raises(DemistoException, match="Failed to parse time string"):
            convert_time_string(invalid_time)

    def test_calculate_event_hash(self):
        """
        Given:
        - Event dictionary with various fields

        When:
        - Calculating hash for the event

        Then:
        - Should return consistent SHA256 hash
        - Same event should produce same hash
        - Different events should produce different hashes
        """
        event1 = {"datetime": "2025-09-27T14:30:00Z", "query": "example.com", "client_ip": "1.2.3.4"}
        event2 = {
            "client_ip": "1.2.3.4",  # Different order
            "query": "example.com",
            "datetime": "2025-09-27T14:30:00Z",
        }
        event3 = {"datetime": "2025-09-27T14:30:00Z", "query": "different.com", "client_ip": "1.2.3.4"}

        hash1 = _calculate_event_hash(event1)
        hash2 = _calculate_event_hash(event2)
        hash3 = _calculate_event_hash(event3)

        assert hash1 == hash2  # Same content, different order should produce same hash
        assert hash1 != hash3  # Different content should produce different hash
        assert len(hash1) == 64  # SHA256 hex string length


class TestDeduplication:
    def test_deduplicate_events_no_duplicates(self):
        """
        Given:
        - List of unique events
        - Empty event cache
        - Upper bound for duplicate checking

        When:
        - Running deduplication

        Then:
        - Should return all events unchanged
        - No events should be filtered out
        """
        events = [
            {"datetime": "2025-09-27T14:29:00Z", "query": "test1.com"},
            {"datetime": "2025-09-27T14:30:00Z", "query": "test2.com"},
        ]
        event_cache = {}
        upper_bound = datetime(2025, 9, 27, 14, 30, 1)

        result = _deduplicate_events(events, event_cache, upper_bound)

        assert len(result) == 2
        assert result == events

    def test_deduplicate_events_with_duplicates(self):
        """
        Given:
        - List of events with some duplicates
        - Event cache containing hashes of previous events
        - Upper bound for duplicate checking

        When:
        - Running deduplication

        Then:
        - Should filter out duplicate events
        - Should keep unique events
        """
        events = [
            {"datetime": "2025-09-27T14:29:00Z", "query": "test1.com"},
            {"datetime": "2025-09-27T14:30:00Z", "query": "test2.com"},
        ]

        # Pre-populate cache with hash of first event
        duplicate_hash = _calculate_event_hash(events[0])
        event_cache = {duplicate_hash: "2025-09-27T14:29:00"}
        upper_bound = datetime(2025, 9, 27, 14, 30, 1)

        result = _deduplicate_events(events, event_cache, upper_bound)

        assert len(result) == 1
        assert result[0] == events[1]  # Second event should remain

    def test_deduplicate_events_boundary_optimization(self):
        """
        Given:
        - List of events with some newer than upper boundary
        - Event cache containing hash of the "newer" event
        - Upper bound for duplicate checking

        When:
        - Running deduplication

        Then:
        - Should add events newer than boundary without duplicate check (ignoring cache)
        - Should check duplicates for events within boundary
        """
        events = [
            {"datetime": "2025-09-27T14:25:00Z", "query": "old.com"},
            {"datetime": "2025-09-27T14:30:00Z", "query": "boundary.com"},
            {"datetime": "2025-09-27T14:35:00Z", "query": "new.com"},  # Newer than boundary
        ]

        # Pre-populate cache with hash of the "new.com" event to test optimization
        new_event_hash = _calculate_event_hash(events[2])
        old_event_hash = _calculate_event_hash(events[0])
        event_cache = {
            new_event_hash: "2025-09-27T14:35:00",  # This should be ignored due to optimization
            old_event_hash: "2025-09-27T14:25:00",  # This should cause old.com to be filtered
        }
        upper_bound = datetime(2025, 9, 27, 14, 30, 1)  # Between second and third event

        result = _deduplicate_events(events, event_cache, upper_bound)

        assert len(result) == 2
        assert result[0]["query"] == "boundary.com"  # Boundary event kept (not in cache)
        assert result[1]["query"] == "new.com"  # Newer event kept despite being in cache


class TestCaching:
    def test_cache_recent_events(self):
        """
        Given:
        - List of events with different timestamps relative to cutoff
        - Empty cache dictionary
        - Cutoff time for caching

        When:
        - Caching recent events

        Then:
        - Should cache events newer than or equal to cutoff
        - Should not cache events older than cutoff
        """
        events = [
            {"datetime": "2025-09-27T14:20:00Z", "query": "old.com"},  # Older
            {"datetime": "2025-09-27T14:25:00Z", "query": "exact.com"},  # Equal to cutoff
            {"datetime": "2025-09-27T14:30:00Z", "query": "recent.com"},  # Newer
        ]

        with patch("UltraDDR._calculate_event_hash") as mock_hash:
            mock_hash.side_effect = ["hash_old", "hash_exact", "hash_recent"]

            cache = {}
            cutoff_time = datetime(2025, 9, 27, 14, 25, 0)

            _cache_recent_events(events, cache, cutoff_time)

            assert len(cache) == 2
            assert "hash_exact" in cache
            assert "hash_recent" in cache
            assert "hash_old" not in cache

            assert cache["hash_exact"] == "2025-09-27T14:25:00"
            assert cache["hash_recent"] == "2025-09-27T14:30:00"

            assert mock_hash.call_count == 2

    def test_cleanup_event_cache(self):
        """
        Given:
        - Event cache with old and recent entries
        - Cutoff time for cleanup

        When:
        - Cleaning up event cache

        Then:
        - Should remove entries older than cutoff
        - Should keep entries newer than cutoff
        """
        event_cache = {
            "hash1": "2025-09-27T14:30:00",  # Recent
            "hash2": "2025-09-27T14:20:00",  # Old
            "hash3": "2025-09-27T14:35:00",  # Recent
        }
        cutoff_time = datetime(2025, 9, 27, 14, 25, 0)

        result = _cleanup_event_cache(event_cache, cutoff_time)

        assert len(result) == 2
        assert "hash1" in result
        assert "hash3" in result
        assert "hash2" not in result

    def test_cleanup_event_cache_invalid_timestamps(self):
        """
        Given:
        - Event cache with some invalid timestamp entries
        - Cutoff time for cleanup

        When:
        - Cleaning up event cache

        Then:
        - Should handle invalid timestamps gracefully
        - Should keep valid entries
        """
        event_cache = {
            "hash1": "2025-09-27T14:30:00",  # Valid
            "hash2": "invalid_timestamp",  # Invalid
            "hash3": "2025-09-27T14:35:00",  # Valid
        }
        cutoff_time = datetime(2025, 9, 27, 14, 25, 0)

        result = _cleanup_event_cache(event_cache, cutoff_time)

        assert "hash1" in result
        assert "hash3" in result


class TestEventProcessing:
    def test_process_events_for_xsiam(self):
        """
        Given:
        - List of events with datetime field

        When:
        - Processing events for XSIAM ingestion

        Then:
        - Should add _time, _vendor, _product, SOURCE_LOG_TYPE fields
        - Should convert datetime to timestamp
        """
        events = [
            {"datetime": "2025-09-27T14:30:00Z", "query": "test.com"},
            {"datetime": "2025-09-27T14:31:00Z", "query": "test2.com"},
        ]

        result = process_events_for_xsiam(events)

        assert len(result) == 2
        for event in result:
            assert "_time" in event
            assert "_vendor" in event
            assert "_product" in event
            assert "SOURCE_LOG_TYPE" in event
            assert event["_vendor"] == VENDOR
            assert event["_product"] == PRODUCT
            assert event["SOURCE_LOG_TYPE"] == "dns"
            assert isinstance(event["_time"], int | float)


class TestMainFunctions:
    def test_test_module_success(self):
        """
        Given:
        - Valid UltraDDR API key
        - Mock API endpoints returning successful responses

        When:
        - Running test module

        Then:
        - Should return "ok" indicating successful connection
        """
        dns_response = util_load_json("test_data/dns_logs_empty.json")

        from UltraDDR import test_module

        with requests_mock.Mocker() as mocker:
            mocker.post(DNS_LOG_URL, json=dns_response)

            client = Client(BASE_URL, API_KEY)
            result = test_module(client, {})

            assert result == "ok"

    def test_test_module_failure(self):
        """
        Given:
        - Invalid UltraDDR API key
        - Mock API endpoints returning authentication errors

        When:
        - Running test module

        Then:
        - Should return error message with authentication failure
        """
        from UltraDDR import test_module

        with requests_mock.Mocker() as mocker:
            mocker.post(DNS_LOG_URL, status_code=401, json={"error": "invalid_api_key"})

            client = Client(BASE_URL, API_KEY)

            result = test_module(client, {})

            assert "Connection failed:" in result

    def test_get_events_command(self, mocker):
        """
        Given:
        - Valid API client and parameters
        - Mock DNS logs endpoint returning events

        When:
        - Running get-events command

        Then:
        - Should fetch events from API
        - Should return CommandResults with events
        - Should optionally push events to XSIAM
        """
        dns_response = util_load_json("test_data/dns_logs.json")

        # Remove nextPageToken to simulate single page response
        dns_response.pop("nextPageToken", None)

        mock_send = mocker.patch("UltraDDR.send_events_to_xsiam", side_effect=mock_send_events_to_xsiam)

        with requests_mock.Mocker() as requests_mocker:
            requests_mocker.post(DNS_LOG_URL, json=dns_response)

            client = Client(BASE_URL, API_KEY)

            args = {
                "limit": "10",
                "start_time": "2025-09-27T14:00:00",
                "end_time": "2025-09-27T15:00:00",
                "should_push_events": "true",
            }

            events, result = get_events_command(client, args)

            assert isinstance(result, CommandResults)
            assert len(events) == 3
            mock_send.assert_called_once()

    @freeze_time("2025-09-27 15:00:00")
    def test_fetch_events_first_run(self):
        """
        Given:
        - Empty last_run state (first fetch)
        - Mock API returning events

        When:
        - Running fetch events

        Then:
        - Should fetch events from last 3 hours
        - Should return proper next_run state
        - Should return processed events
        """
        dns_response = util_load_json("test_data/dns_logs.json")

        dns_response.pop("nextPageToken", None)

        with requests_mock.Mocker() as mocker:
            mocker.post(DNS_LOG_URL, json=dns_response)

            client = Client(BASE_URL, API_KEY)
            last_run = {}

            next_run, events = fetch_events(client=client, last_run=last_run, max_events_per_fetch=100)

            assert "last_fetch_time" in next_run
            assert "event_cache" in next_run
            assert len(events) == 3
            assert all("_time" in event for event in events)
            assert all("_vendor" in event for event in events)
            assert all("SOURCE_LOG_TYPE" in event for event in events)

    @freeze_time("2025-09-27 15:00:00")
    def test_fetch_events_no_new_events(self):
        """
        Given:
        - Previous last_run state
        - Mock API returning no new events

        When:
        - Running fetch events

        Then:
        - Should return unchanged last_run state
        - Should return empty events list
        """
        dns_response = util_load_json("test_data/dns_logs_empty.json")

        with requests_mock.Mocker() as mocker:
            mocker.post(DNS_LOG_URL, json=dns_response)

            client = Client(BASE_URL, API_KEY)
            last_run = {"last_fetch_time": "2025-09-27T14:25:00", "event_cache": {"test_hash": "2025-09-27T14:20:00"}}

            next_run, events = fetch_events(client=client, last_run=last_run, max_events_per_fetch=100)

            assert next_run == last_run
            assert len(events) == 0

    @freeze_time("2025-09-27 15:00:00")
    def test_fetch_events_deduplication_end_to_end(self):
        """
        Given:
        - Previous last_run with timestamp and cached event hashes
        - Mock API returning events including duplicates

        When:
        - Running fetch events

        Then:
        - Should use last_fetch_time - 3s for API call
        - Should deduplicate using cached hashes
        - Should update next_run with exact timestamp and cache values
        - Should clean up old cache entries
        """
        test_events = util_load_json("test_data/dns_logs.json")

        duplicate_event = test_events["logs"][0]
        duplicate_hash = _calculate_event_hash(duplicate_event)

        last_event = test_events["logs"][2]
        last_hash = _calculate_event_hash(last_event)

        test_events.pop("nextPageToken", None)

        with requests_mock.Mocker() as mocker:
            mocker.post(DNS_LOG_URL, json=test_events)

            client = Client(BASE_URL, API_KEY)

            old_hash = "old_hash_should_be_cleaned"
            last_run = {
                "last_fetch_time": "2025-09-27T14:30:05",
                "event_cache": {
                    duplicate_hash: "2025-09-27T14:30:00",
                    old_hash: "2025-09-27T14:20:00",
                },
            }

            next_run, events = fetch_events(client=client, last_run=last_run, max_events_per_fetch=100)

            assert len(events) == 2

            assert next_run["last_fetch_time"] == "2025-09-27T14:32:30"

            expected_cache = {
                last_hash: "2025-09-27T14:32:30",
            }
            assert next_run["event_cache"] == expected_cache

            returned_timestamps = [event["datetime"] for event in events]
            expected_timestamps = ["2025-09-27T14:31:15Z", "2025-09-27T14:32:30Z"]
            assert returned_timestamps == expected_timestamps