#!/usr/bin/env python3
"""
Property-based tests for category toggle behavior in content enrichment.
Tests that content categories can be toggled on/off correctly.
"""

import pytest
from hypothesis import given, strategies as st

# Mock content categories
CONTENT_CATEGORIES = [
    'security',
    'ai-ml',
    'best-practices',
    'cost-optimization',
    'performance',
    'reliability'
]

def create_mock_content_item(category, title="Test Article", relevance_score=0.8):
    """Create a mock content item for testing"""
    return {
        'id': f"{category}-{hash(title) % 1000}",
        'title': title,
        'url': f'https://aws.amazon.com/blog/{category}/test/',
        'description': f'Test description for {category}',
        'category': category,
        'relevance_score': relevance_score,
        'published_date': '2024-01-01',
        'source': 'aws.amazon.com'
    }

class CategoryToggleManager:
    """Simulates the category toggle functionality from ContentEnrichment.jsx"""
    
    def __init__(self):
        self.visible_categories = set(CONTENT_CATEGORIES)  # All visible by default
        self.content_items = []
    
    def setContentItems(self, items):
        """Set the content items to manage"""
        self.content_items = items
    
    def toggleCategory(self, category):
        """Toggle visibility of a category"""
        if category in self.visible_categories:
            self.visible_categories.remove(category)
        else:
            self.visible_categories.add(category)
    
    def setCategoryVisible(self, category, visible):
        """Set category visibility explicitly"""
        if visible:
            self.visible_categories.add(category)
        else:
            self.visible_categories.discard(category)
    
    def isCategoryVisible(self, category):
        """Check if a category is visible"""
        return category in self.visible_categories
    
    def getVisibleItems(self):
        """Get items from visible categories only"""
        return [item for item in self.content_items 
                if item['category'] in self.visible_categories]
    
    def getVisibleCategories(self):
        """Get list of visible categories"""
        return list(self.visible_categories)
    
    def getItemsByCategory(self, category):
        """Get all items in a specific category"""
        return [item for item in self.content_items 
                if item['category'] == category]

@given(
    content_data=st.dictionaries(
        keys=st.sampled_from(CONTENT_CATEGORIES),
        values=st.lists(
            st.builds(
                create_mock_content_item,
                category=st.sampled_from(CONTENT_CATEGORIES),
                title=st.text(min_size=5, max_size=50),
                relevance_score=st.floats(min_value=0.0, max_value=1.0)
            ),
            min_size=1,
            max_size=5
        ),
        min_size=1,
        max_size=len(CONTENT_CATEGORIES)
    )
)
def test_category_toggle_behavior_property(content_data):
    """
    Property 11: Category Toggle Behavior
    Validates: Requirements 5.2
    
    Tests that category toggles work correctly:
    - Categories can be toggled on/off
    - Content visibility follows category state
    - Toggle state is maintained consistently
    - All categories can be toggled independently
    """
    # Flatten content data into items list
    all_items = []
    for category, items in content_data.items():
        for item in items:
            # Ensure item category matches the key
            item['category'] = category
            all_items.append(item)
    
    toggle_manager = CategoryToggleManager()
    toggle_manager.setContentItems(all_items)
    
    categories_in_data = list(content_data.keys())
    
    # Property 1: All categories start visible by default
    for category in categories_in_data:
        assert toggle_manager.isCategoryVisible(category), f"Category {category} should be visible by default"
    
    # Property 2: All items are visible when all categories are visible
    visible_items = toggle_manager.getVisibleItems()
    assert len(visible_items) == len(all_items), "All items should be visible when all categories are visible"
    
    # Property 3: Toggling a category off hides its items
    for category in categories_in_data:
        # Count items in this category
        category_items = toggle_manager.getItemsByCategory(category)
        initial_visible_count = len(toggle_manager.getVisibleItems())
        
        # Toggle category off
        toggle_manager.toggleCategory(category)
        assert not toggle_manager.isCategoryVisible(category), f"Category {category} should be hidden after toggle"
        
        # Check that items are hidden
        visible_after_toggle = toggle_manager.getVisibleItems()
        expected_count = initial_visible_count - len(category_items)
        assert len(visible_after_toggle) == expected_count, f"Visible items should decrease by {len(category_items)}"
        
        # Verify none of the category's items are visible
        for item in category_items:
            assert item not in visible_after_toggle, f"Item {item['id']} should be hidden when category {category} is off"
        
        # Toggle category back on
        toggle_manager.toggleCategory(category)
        assert toggle_manager.isCategoryVisible(category), f"Category {category} should be visible after toggle back"
        
        # Check that items are visible again
        visible_after_restore = toggle_manager.getVisibleItems()
        assert len(visible_after_restore) == initial_visible_count, "All items should be visible again"
    
    # Property 4: Multiple categories can be toggled independently
    if len(categories_in_data) >= 2:
        cat1, cat2 = categories_in_data[0], categories_in_data[1]
        
        # Toggle first category off
        toggle_manager.setCategoryVisible(cat1, False)
        assert not toggle_manager.isCategoryVisible(cat1), f"Category {cat1} should be off"
        assert toggle_manager.isCategoryVisible(cat2), f"Category {cat2} should still be on"
        
        # Toggle second category off
        toggle_manager.setCategoryVisible(cat2, False)
        assert not toggle_manager.isCategoryVisible(cat1), f"Category {cat1} should still be off"
        assert not toggle_manager.isCategoryVisible(cat2), f"Category {cat2} should now be off"
        
        # Toggle first category back on
        toggle_manager.setCategoryVisible(cat1, True)
        assert toggle_manager.isCategoryVisible(cat1), f"Category {cat1} should be on"
        assert not toggle_manager.isCategoryVisible(cat2), f"Category {cat2} should still be off"
    
    # Property 5: Toggling all categories off shows no items
    for category in categories_in_data:
        toggle_manager.setCategoryVisible(category, False)
    
    visible_when_all_off = toggle_manager.getVisibleItems()
    assert len(visible_when_all_off) == 0, "No items should be visible when all categories are off"
    
    # Property 6: Toggling all categories back on shows all items
    for category in categories_in_data:
        toggle_manager.setCategoryVisible(category, True)
    
    visible_when_all_on = toggle_manager.getVisibleItems()
    assert len(visible_when_all_on) == len(all_items), "All items should be visible when all categories are on"

def test_category_toggle_edge_cases():
    """Test edge cases for category toggling"""
    toggle_manager = CategoryToggleManager()
    
    # Test with empty content
    toggle_manager.setContentItems([])
    visible_items = toggle_manager.getVisibleItems()
    assert len(visible_items) == 0, "Should handle empty content gracefully"
    
    # Test toggling non-existent category
    toggle_manager.toggleCategory('non-existent-category')
    # Should not crash and should add the category to visible set
    assert toggle_manager.isCategoryVisible('non-existent-category'), "Non-existent category should be added when toggled"
    
    # Test with items having unknown categories
    unknown_category_item = create_mock_content_item('unknown-category', 'Unknown Category Item')
    toggle_manager.setContentItems([unknown_category_item])
    
    # Unknown category items should not be visible initially
    visible_items = toggle_manager.getVisibleItems()
    assert len(visible_items) == 0, "Items with unknown categories should not be visible initially"
    
    # Make unknown category visible
    toggle_manager.setCategoryVisible('unknown-category', True)
    visible_items = toggle_manager.getVisibleItems()
    assert len(visible_items) == 1, "Items should be visible when their category is made visible"

def test_category_state_consistency():
    """Test that category toggle state remains consistent"""
    toggle_manager = CategoryToggleManager()
    
    # Create test content with multiple categories
    test_items = [
        create_mock_content_item('security', 'Security Article 1'),
        create_mock_content_item('security', 'Security Article 2'),
        create_mock_content_item('ai-ml', 'AI/ML Article 1'),
        create_mock_content_item('best-practices', 'Best Practices Article 1')
    ]
    
    toggle_manager.setContentItems(test_items)
    
    # Test multiple toggle operations
    operations = [
        ('security', False),
        ('ai-ml', False),
        ('security', True),
        ('best-practices', False),
        ('ai-ml', True)
    ]
    
    expected_state = {'security': True, 'ai-ml': True, 'best-practices': False}
    
    for category, visible in operations:
        toggle_manager.setCategoryVisible(category, visible)
    
    # Verify final state
    for category, expected_visible in expected_state.items():
        actual_visible = toggle_manager.isCategoryVisible(category)
        assert actual_visible == expected_visible, f"Category {category} state should be {expected_visible}, got {actual_visible}"
    
    # Verify visible items match expected state
    visible_items = toggle_manager.getVisibleItems()
    expected_visible_items = [item for item in test_items if expected_state.get(item['category'], True)]
    
    assert len(visible_items) == len(expected_visible_items), "Visible items count should match expected state"
    
    for item in expected_visible_items:
        assert item in visible_items, f"Item {item['id']} should be visible based on category state"

def test_category_toggle_performance():
    """Test that category toggling performs well with many items"""
    toggle_manager = CategoryToggleManager()
    
    # Create large dataset
    large_dataset = []
    for category in CONTENT_CATEGORIES:
        for i in range(100):  # 100 items per category
            item = create_mock_content_item(category, f'{category} Article {i}')
            large_dataset.append(item)
    
    toggle_manager.setContentItems(large_dataset)
    
    # Test that operations complete quickly (no specific timing, just that they don't hang)
    for category in CONTENT_CATEGORIES:
        toggle_manager.toggleCategory(category)
        visible_items = toggle_manager.getVisibleItems()
        # Just verify the operation completes
        assert isinstance(visible_items, list), "Should return list of visible items"
    
    # Verify final state is correct
    # All categories should be off after toggling each once
    visible_items = toggle_manager.getVisibleItems()
    assert len(visible_items) == 0, "All items should be hidden after toggling all categories off"

if __name__ == "__main__":
    # Run a simple test
    test_category_toggle_edge_cases()
    print("✅ Category toggle tests passed")