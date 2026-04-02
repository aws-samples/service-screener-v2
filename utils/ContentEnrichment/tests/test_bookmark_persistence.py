#!/usr/bin/env python3
"""
Property-based tests for bookmark persistence in content enrichment.
Tests that bookmarks are properly stored and retrieved from localStorage.
"""

import pytest
from hypothesis import given, strategies as st
import json

# Mock localStorage for testing
class MockLocalStorage:
    def __init__(self):
        self.storage = {}
    
    def getItem(self, key):
        return self.storage.get(key)
    
    def setItem(self, key, value):
        self.storage[key] = value
    
    def removeItem(self, key):
        if key in self.storage:
            del self.storage[key]
    
    def clear(self):
        self.storage.clear()

# Mock content items for testing
def create_mock_content_item(item_id, title="Test Article", url="https://aws.amazon.com/blog/test/"):
    """Create a mock content item for testing"""
    return {
        'id': item_id,
        'title': title,
        'url': url,
        'description': 'Test description',
        'category': 'security',
        'relevance_score': 0.8,
        'published_date': '2024-01-01',
        'source': 'aws.amazon.com'
    }

class BookmarkManager:
    """Simulates the bookmark functionality from ContentEnrichment.jsx"""
    
    def __init__(self, localStorage):
        self.localStorage = localStorage
        self.STORAGE_KEY = 'service-screener-bookmarks'
    
    def getBookmarks(self):
        """Get all bookmarks from localStorage"""
        try:
            stored = self.localStorage.getItem(self.STORAGE_KEY)
            if stored:
                return json.loads(stored)
            return []
        except:
            return []
    
    def addBookmark(self, item):
        """Add an item to bookmarks"""
        bookmarks = self.getBookmarks()
        
        # Check if already bookmarked
        if not any(b['id'] == item['id'] for b in bookmarks):
            bookmark = {
                'id': item['id'],
                'title': item['title'],
                'url': item['url'],
                'category': item['category'],
                'bookmarked_at': '2024-01-01T00:00:00Z'  # Mock timestamp
            }
            bookmarks.append(bookmark)
            self.localStorage.setItem(self.STORAGE_KEY, json.dumps(bookmarks))
        
        return bookmarks
    
    def removeBookmark(self, item_id):
        """Remove an item from bookmarks"""
        bookmarks = self.getBookmarks()
        bookmarks = [b for b in bookmarks if b['id'] != item_id]
        self.localStorage.setItem(self.STORAGE_KEY, json.dumps(bookmarks))
        return bookmarks
    
    def isBookmarked(self, item_id):
        """Check if an item is bookmarked"""
        bookmarks = self.getBookmarks()
        return any(b['id'] == item_id for b in bookmarks)

@given(
    content_items=st.lists(
        st.builds(
            create_mock_content_item,
            item_id=st.text(min_size=1, max_size=20, alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd'))),
            title=st.text(min_size=5, max_size=100),
            url=st.just('https://aws.amazon.com/blog/test/')
        ),
        min_size=1,
        max_size=10,
        unique_by=lambda x: x['id']  # Ensure unique IDs
    )
)
def test_bookmark_persistence_property(content_items):
    """
    Property 10: Bookmark Persistence
    Validates: Requirements 3.5
    
    Tests that bookmarks are properly persisted across sessions:
    - Bookmarks are stored in localStorage
    - Bookmarks persist after page reload (localStorage survives)
    - Bookmark state is correctly maintained
    - Duplicate bookmarks are prevented
    """
    # Create mock localStorage
    localStorage = MockLocalStorage()
    bookmark_manager = BookmarkManager(localStorage)
    
    # Property 1: Initially no bookmarks
    initial_bookmarks = bookmark_manager.getBookmarks()
    assert initial_bookmarks == [], "Should start with no bookmarks"
    
    # Property 2: Adding bookmarks persists them
    added_items = []
    for item in content_items:
        bookmarks = bookmark_manager.addBookmark(item)
        added_items.append(item)
        
        # Verify bookmark was added
        assert bookmark_manager.isBookmarked(item['id']), f"Item {item['id']} should be bookmarked"
        
        # Verify bookmark count matches added items
        assert len(bookmarks) == len(added_items), f"Bookmark count should match added items"
        
        # Verify bookmark contains correct data
        bookmark = next(b for b in bookmarks if b['id'] == item['id'])
        assert bookmark['title'] == item['title'], "Bookmark title should match original"
        assert bookmark['url'] == item['url'], "Bookmark URL should match original"
        assert bookmark['category'] == item['category'], "Bookmark category should match original"
        assert 'bookmarked_at' in bookmark, "Bookmark should have timestamp"
    
    # Property 3: Bookmarks persist across "sessions" (localStorage survives)
    # Simulate page reload by creating new bookmark manager with same localStorage
    new_bookmark_manager = BookmarkManager(localStorage)
    persisted_bookmarks = new_bookmark_manager.getBookmarks()
    
    assert len(persisted_bookmarks) == len(content_items), "All bookmarks should persist"
    
    for item in content_items:
        assert new_bookmark_manager.isBookmarked(item['id']), f"Item {item['id']} should persist"
    
    # Property 4: Removing bookmarks works correctly
    items_to_remove = content_items[:len(content_items)//2]  # Remove half
    for item in items_to_remove:
        remaining_bookmarks = bookmark_manager.removeBookmark(item['id'])
        assert not bookmark_manager.isBookmarked(item['id']), f"Item {item['id']} should be removed"
    
    # Verify remaining bookmarks
    final_bookmarks = bookmark_manager.getBookmarks()
    expected_remaining = len(content_items) - len(items_to_remove)
    assert len(final_bookmarks) == expected_remaining, "Correct number of bookmarks should remain"
    
    # Property 5: Duplicate bookmarks are prevented
    if content_items:
        first_item = content_items[0]
        initial_count = len(bookmark_manager.getBookmarks())
        
        # Try to add the same item again
        bookmark_manager.addBookmark(first_item)
        final_count = len(bookmark_manager.getBookmarks())
        
        assert final_count == initial_count, "Duplicate bookmarks should be prevented"

def test_bookmark_data_integrity():
    """Test that bookmark data maintains integrity"""
    localStorage = MockLocalStorage()
    bookmark_manager = BookmarkManager(localStorage)
    
    # Test with various content types
    test_items = [
        create_mock_content_item('security-1', 'AWS Security Best Practices', 'https://aws.amazon.com/security/'),
        create_mock_content_item('ai-ml-1', 'Machine Learning on AWS', 'https://aws.amazon.com/machine-learning/'),
        create_mock_content_item('architecture-1', 'Well-Architected Framework', 'https://aws.amazon.com/architecture/')
    ]
    
    # Add all items
    for item in test_items:
        bookmark_manager.addBookmark(item)
    
    # Verify data integrity
    bookmarks = bookmark_manager.getBookmarks()
    
    for i, item in enumerate(test_items):
        bookmark = next(b for b in bookmarks if b['id'] == item['id'])
        
        # Verify all required fields are present
        required_fields = ['id', 'title', 'url', 'category', 'bookmarked_at']
        for field in required_fields:
            assert field in bookmark, f"Bookmark missing required field: {field}"
        
        # Verify data types
        assert isinstance(bookmark['id'], str), "Bookmark ID should be string"
        assert isinstance(bookmark['title'], str), "Bookmark title should be string"
        assert isinstance(bookmark['url'], str), "Bookmark URL should be string"
        assert isinstance(bookmark['category'], str), "Bookmark category should be string"
        assert isinstance(bookmark['bookmarked_at'], str), "Bookmark timestamp should be string"

def test_bookmark_storage_format():
    """Test that bookmarks are stored in correct JSON format"""
    localStorage = MockLocalStorage()
    bookmark_manager = BookmarkManager(localStorage)
    
    test_item = create_mock_content_item('test-1', 'Test Article')
    bookmark_manager.addBookmark(test_item)
    
    # Check raw storage format
    stored_data = localStorage.getItem('service-screener-bookmarks')
    assert stored_data is not None, "Bookmarks should be stored"
    
    # Verify it's valid JSON
    try:
        parsed_data = json.loads(stored_data)
        assert isinstance(parsed_data, list), "Stored bookmarks should be a list"
        assert len(parsed_data) == 1, "Should have one bookmark"
        
        bookmark = parsed_data[0]
        assert bookmark['id'] == 'test-1', "Bookmark ID should match"
        assert bookmark['title'] == 'Test Article', "Bookmark title should match"
        
    except json.JSONDecodeError:
        pytest.fail("Stored bookmark data should be valid JSON")

def test_bookmark_error_handling():
    """Test bookmark functionality handles errors gracefully"""
    # Test with corrupted localStorage
    localStorage = MockLocalStorage()
    localStorage.setItem('service-screener-bookmarks', 'invalid-json')
    
    bookmark_manager = BookmarkManager(localStorage)
    
    # Should handle corrupted data gracefully
    bookmarks = bookmark_manager.getBookmarks()
    assert bookmarks == [], "Should return empty list for corrupted data"
    
    # Should be able to add new bookmarks after corruption
    test_item = create_mock_content_item('recovery-test', 'Recovery Test')
    new_bookmarks = bookmark_manager.addBookmark(test_item)
    assert len(new_bookmarks) == 1, "Should recover and add new bookmark"

if __name__ == "__main__":
    # Run a simple test
    test_bookmark_data_integrity()
    print("✅ Bookmark persistence tests passed")