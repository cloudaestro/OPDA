"""Tests for pagination functionality."""

from unittest.mock import AsyncMock, Mock

import pytest

from opda.client.pagination import OktaPaginator, PaginationError


class TestOktaPaginator:
    """Test OktaPaginator functionality."""

    @pytest.fixture
    def paginator(self) -> OktaPaginator:
        """Create paginator with test configuration."""
        return OktaPaginator(page_size=5, max_pages=10, max_items=50)

    @pytest.mark.asyncio
    async def test_paginate_all_with_list_response(
        self, paginator: OktaPaginator
    ) -> None:
        """Test pagination with simple list responses."""
        mock_fetch = AsyncMock()
        mock_fetch.side_effect = [
            ["item1", "item2", "item3"],  # First page
            ["item4", "item5"],  # Second page (partial)
            [],  # Empty page (end of results)
        ]

        results = await paginator.paginate_all(mock_fetch)

        assert len(results) == 5
        assert results == ["item1", "item2", "item3", "item4", "item5"]
        assert mock_fetch.call_count == 2  # Should stop when empty page returned

    @pytest.mark.asyncio
    async def test_paginate_all_with_dict_response(
        self, paginator: OktaPaginator
    ) -> None:
        """Test pagination with dictionary responses containing items."""
        mock_fetch = AsyncMock()
        mock_fetch.side_effect = [
            {
                "items": ["user1", "user2", "user3"],
                "pagination": {"next": "cursor123"},
            },
            {
                "items": ["user4", "user5"],
                "pagination": {},
            },
        ]

        results = await paginator.paginate_all(mock_fetch)

        assert len(results) == 5
        assert results == ["user1", "user2", "user3", "user4", "user5"]

    @pytest.mark.asyncio
    async def test_cursor_based_pagination(self, paginator: OktaPaginator) -> None:
        """Test cursor-based pagination parameter handling."""
        mock_fetch = AsyncMock()
        mock_fetch.side_effect = [
            {
                "items": ["item1", "item2"],
                "links": {
                    "next": {"href": "https://api.okta.com/api/v1/users?after=cursor123"}
                },
            },
            {
                "items": ["item3", "item4"],
                "links": {},
            },
        ]

        results = await paginator.paginate_all(mock_fetch, test_param="value")

        assert len(results) == 4
        assert mock_fetch.call_count == 2

        # Check that cursor was properly extracted and used
        first_call_kwargs = mock_fetch.call_args_list[0][1]
        second_call_kwargs = mock_fetch.call_args_list[1][1]

        assert "after" not in first_call_kwargs
        assert second_call_kwargs["after"] == "cursor123"

    @pytest.mark.asyncio
    async def test_offset_based_pagination(self, paginator: OktaPaginator) -> None:
        """Test offset-based pagination fallback."""
        mock_fetch = AsyncMock()
        mock_fetch.side_effect = [
            ["item1", "item2", "item3", "item4", "item5"],  # Full page
            ["item6", "item7"],  # Partial page (end of results)
        ]

        results = await paginator.paginate_all(mock_fetch)

        assert len(results) == 7
        assert mock_fetch.call_count == 2

        # Check offset progression
        first_call_kwargs = mock_fetch.call_args_list[0][1]
        second_call_kwargs = mock_fetch.call_args_list[1][1]

        assert first_call_kwargs["offset"] == 0
        assert second_call_kwargs["offset"] == 5

    @pytest.mark.asyncio
    async def test_max_pages_limit(self, paginator: OktaPaginator) -> None:
        """Test maximum pages limit enforcement."""
        paginator.max_pages = 2

        mock_fetch = AsyncMock()
        mock_fetch.side_effect = [
            ["item1", "item2", "item3"],
            ["item4", "item5", "item6"],
            ["item7", "item8", "item9"],  # This should not be called
        ]

        results = await paginator.paginate_all(mock_fetch)

        assert len(results) == 6  # Only first 2 pages
        assert mock_fetch.call_count == 2

    @pytest.mark.asyncio
    async def test_max_items_limit(self, paginator: OktaPaginator) -> None:
        """Test maximum items limit enforcement."""
        paginator.max_items = 4

        mock_fetch = AsyncMock()
        mock_fetch.side_effect = [
            ["item1", "item2", "item3"],
            ["item4", "item5", "item6"],  # More items than limit
        ]

        results = await paginator.paginate_all(mock_fetch)

        assert len(results) == 4  # Should be limited to max_items
        assert results == ["item1", "item2", "item3", "item4"]

    @pytest.mark.asyncio
    async def test_pagination_error_handling(self, paginator: OktaPaginator) -> None:
        """Test error handling during pagination."""
        mock_fetch = AsyncMock()
        mock_fetch.side_effect = [
            ["item1", "item2"],
            Exception("API error"),
        ]

        with pytest.raises(PaginationError, match="Failed to fetch page 2"):
            await paginator.paginate_all(mock_fetch)

    @pytest.mark.asyncio
    async def test_sync_function_execution_in_paginator(
        self, paginator: OktaPaginator
    ) -> None:
        """Test that sync functions work with paginator."""
        mock_func = Mock()
        mock_func.side_effect = [
            ["item1", "item2"],
            [],  # End of results
        ]

        results = await paginator.paginate_all(mock_func)

        assert len(results) == 2
        assert results == ["item1", "item2"]

    def test_statistics_tracking(self, paginator: OktaPaginator) -> None:
        """Test statistics tracking."""
        stats = paginator.get_statistics()

        assert stats["pages_fetched"] == 0
        assert stats["items_fetched"] == 0
        assert stats["total_api_calls"] == 0
        assert stats["page_size"] == 5
        assert stats["max_pages"] == 10
        assert stats["max_items"] == 50

    def test_statistics_reset(self, paginator: OktaPaginator) -> None:
        """Test statistics reset."""
        # Manually set some statistics
        paginator._pages_fetched = 5
        paginator._items_fetched = 25
        paginator._total_api_calls = 7

        paginator.reset_statistics()

        stats = paginator.get_statistics()
        assert stats["pages_fetched"] == 0
        assert stats["items_fetched"] == 0
        assert stats["total_api_calls"] == 0

    def test_extract_items_from_various_responses(
        self, paginator: OktaPaginator
    ) -> None:
        """Test item extraction from different response formats."""
        # List response
        list_response = ["item1", "item2"]
        items = paginator._extract_items_from_response(list_response)
        assert items == ["item1", "item2"]

        # Dict with 'items' key
        dict_items_response = {"items": ["user1", "user2"]}
        items = paginator._extract_items_from_response(dict_items_response)
        assert items == ["user1", "user2"]

        # Dict with 'results' key
        dict_results_response = {"results": ["result1", "result2"]}
        items = paginator._extract_items_from_response(dict_results_response)
        assert items == ["result1", "result2"]

        # Single item
        single_item = {"id": "item1", "name": "test"}
        items = paginator._extract_items_from_response(single_item)
        assert items == [single_item]

        # Empty/None response
        empty_items = paginator._extract_items_from_response(None)
        assert empty_items == []

    def test_extract_next_cursor(self, paginator: OktaPaginator) -> None:
        """Test cursor extraction from various response formats."""
        # Pagination metadata
        response_with_pagination = {
            "items": ["item1"],
            "pagination": {"next": "cursor123"},
        }
        cursor = paginator._extract_next_cursor(response_with_pagination)
        assert cursor == "cursor123"

        # Links-based pagination
        response_with_links = {
            "items": ["item1"],
            "links": {
                "next": {"href": "https://api.okta.com/api/v1/users?after=cursor456"}
            },
        }
        cursor = paginator._extract_next_cursor(response_with_links)
        assert cursor == "cursor456"

        # Direct cursor field
        response_with_cursor = {
            "items": ["item1"],
            "cursor": "direct_cursor789",
        }
        cursor = paginator._extract_next_cursor(response_with_cursor)
        assert cursor == "direct_cursor789"

        # No cursor (end of results)
        response_no_cursor = {"items": ["item1"]}
        cursor = paginator._extract_next_cursor(response_no_cursor)
        assert cursor is None

    @pytest.mark.asyncio
    async def test_async_generator_pagination(self, paginator: OktaPaginator) -> None:
        """Test async generator functionality."""
        mock_fetch = AsyncMock()
        mock_fetch.side_effect = [
            ["batch1_item1", "batch1_item2"],
            ["batch2_item1", "batch2_item2"],
            [],  # End of results
        ]

        batches = []
        async for batch in paginator.paginate_async(mock_fetch):
            batches.append(batch)

        assert len(batches) == 2
        assert batches[0] == ["batch1_item1", "batch1_item2"]
        assert batches[1] == ["batch2_item1", "batch2_item2"]

    @pytest.mark.asyncio
    async def test_page_size_enforcement(self) -> None:
        """Test page size is properly enforced."""
        # Page size larger than Okta maximum should be capped
        large_paginator = OktaPaginator(page_size=500)
        assert large_paginator.page_size == 200  # Okta maximum

        # Normal page size should be preserved
        normal_paginator = OktaPaginator(page_size=100)
        assert normal_paginator.page_size == 100
