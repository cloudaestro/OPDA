"""
Generic pagination handler for Okta API responses.

Handles cursor-based and offset-based pagination with
automatic continuation and result aggregation.
"""

import asyncio
from collections.abc import AsyncIterator, Callable
from typing import Any, TypeVar

import structlog

T = TypeVar("T")

logger = structlog.get_logger(__name__)


class PaginationError(Exception):
    """Raised when pagination fails."""

    def __init__(self, message: str, last_cursor: str | None = None) -> None:
        super().__init__(message)
        self.last_cursor = last_cursor


class OktaPaginator:
    """
    Generic paginator for Okta API responses.

    Supports both cursor-based pagination (preferred) and offset-based
    pagination for different Okta endpoints.
    """

    def __init__(
        self,
        page_size: int = 200,
        max_pages: int | None = None,
        max_items: int | None = None,
    ) -> None:
        self.page_size = min(page_size, 200)  # Okta max is 200
        self.max_pages = max_pages
        self.max_items = max_items

        # Statistics
        self._pages_fetched = 0
        self._items_fetched = 0
        self._total_api_calls = 0

    async def paginate_all(
        self,
        fetch_func: Callable[..., Any],
        *args: Any,
        **kwargs: Any,
    ) -> list[Any]:
        """
        Paginate through all results and return complete list.

        Args:
            fetch_func: Function to call for each page
            *args: Positional arguments for fetch_func
            **kwargs: Keyword arguments for fetch_func

        Returns:
            Complete list of all items across all pages
        """
        all_items: list[Any] = []

        async for items in self.paginate_async(fetch_func, *args, **kwargs):
            all_items.extend(items)

            # Check max items limit
            if self.max_items and len(all_items) >= self.max_items:
                all_items = all_items[: self.max_items]
                logger.info(
                    "Reached maximum items limit",
                    max_items=self.max_items,
                    total_fetched=len(all_items),
                )
                break

        logger.info(
            "Pagination completed",
            total_items=len(all_items),
            pages_fetched=self._pages_fetched,
            api_calls=self._total_api_calls,
        )

        return all_items

    async def paginate_async(
        self,
        fetch_func: Callable[..., Any],
        *args: Any,
        **kwargs: Any,
    ) -> AsyncIterator[list[Any]]:
        """
        Async generator that yields pages of results.

        Args:
            fetch_func: Function to call for each page
            *args: Positional arguments for fetch_func
            **kwargs: Keyword arguments for fetch_func

        Yields:
            List of items for each page
        """
        cursor: str | None = None
        offset = 0

        while True:
            # Check page limit
            if self.max_pages and self._pages_fetched >= self.max_pages:
                logger.info(
                    "Reached maximum pages limit",
                    max_pages=self.max_pages,
                    pages_fetched=self._pages_fetched,
                )
                break

            try:
                # Prepare request parameters
                request_kwargs = kwargs.copy()
                request_kwargs["limit"] = self.page_size

                # Add pagination parameters
                if cursor:
                    request_kwargs["after"] = cursor
                else:
                    request_kwargs["offset"] = offset

                logger.debug(
                    "Fetching page",
                    page=self._pages_fetched + 1,
                    cursor=cursor,
                    offset=offset,
                    limit=self.page_size,
                )

                # Execute the fetch function
                self._total_api_calls += 1
                response = await self._execute_fetch(
                    fetch_func, *args, **request_kwargs
                )

                # Extract items from response
                items = self._extract_items_from_response(response)

                if not items:
                    logger.debug("No more items found, stopping pagination")
                    break

                self._pages_fetched += 1
                self._items_fetched += len(items)

                logger.debug(
                    "Page fetched successfully",
                    page=self._pages_fetched,
                    items_in_page=len(items),
                    total_items=self._items_fetched,
                )

                yield items

                # Check for next page
                cursor = self._extract_next_cursor(response)
                if not cursor:
                    # Try offset-based pagination if no cursor
                    offset += self.page_size

                    # If we got fewer items than page size, we're done
                    if len(items) < self.page_size:
                        logger.debug("Reached end of results (partial page)")
                        break
                else:
                    # Reset offset when using cursor
                    offset = 0

            except Exception as e:
                logger.error(
                    "Pagination failed",
                    error=str(e),
                    page=self._pages_fetched + 1,
                    cursor=cursor,
                    offset=offset,
                )
                raise PaginationError(
                    f"Failed to fetch page {self._pages_fetched + 1}: {e}",
                    last_cursor=cursor,
                ) from e

    async def _execute_fetch(
        self, func: Callable[..., Any], *args: Any, **kwargs: Any
    ) -> Any:
        """Execute fetch function handling both sync and async."""
        if asyncio.iscoroutinefunction(func):
            return await func(*args, **kwargs)
        else:
            # Run sync function in thread pool to avoid blocking
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, lambda: func(*args, **kwargs))

    def _extract_items_from_response(self, response: Any) -> list[Any]:
        """Extract items from Okta API response."""
        # Handle different response formats
        if isinstance(response, list):
            return response
        elif isinstance(response, dict):
            # Common Okta response patterns
            if "items" in response:
                return response["items"]
            elif "results" in response:
                return response["results"]
            elif "data" in response:
                return response["data"]
            else:
                # Assume the dict itself contains the data
                return [response]
        else:
            # Single item response
            return [response] if response else []

    def _extract_next_cursor(self, response: Any) -> str | None:
        """Extract next page cursor from response."""
        if not isinstance(response, dict):
            return None

        # Check for pagination metadata
        if "pagination" in response:
            pagination = response["pagination"]
            return pagination.get("next") or pagination.get("cursor")

        # Check for link-based pagination
        if "links" in response:
            links = response["links"]
            next_link = links.get("next")
            if next_link and isinstance(next_link, dict):
                href = next_link.get("href", "")
                # Extract cursor from URL parameters
                if "after=" in href:
                    return href.split("after=")[1].split("&")[0]

        # Check for direct cursor field
        return response.get("cursor") or response.get("next_cursor")

    def get_statistics(self) -> dict[str, Any]:
        """Get pagination statistics."""
        return {
            "pages_fetched": self._pages_fetched,
            "items_fetched": self._items_fetched,
            "total_api_calls": self._total_api_calls,
            "average_items_per_page": (
                self._items_fetched / self._pages_fetched
                if self._pages_fetched > 0
                else 0
            ),
            "page_size": self.page_size,
            "max_pages": self.max_pages,
            "max_items": self.max_items,
        }

    def reset_statistics(self) -> None:
        """Reset pagination statistics."""
        self._pages_fetched = 0
        self._items_fetched = 0
        self._total_api_calls = 0
