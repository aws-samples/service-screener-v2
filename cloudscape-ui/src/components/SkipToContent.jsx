import React from 'react';
import './SkipToContent.css';

/**
 * SkipToContent component
 * Provides a "Skip to main content" link for keyboard users
 * This improves accessibility by allowing users to bypass navigation
 */
const SkipToContent = () => {
  const handleSkip = (e) => {
    e.preventDefault();
    const mainContent = document.getElementById('main-content');
    if (mainContent) {
      mainContent.focus();
      mainContent.scrollIntoView();
    }
  };

  return (
    <a 
      href="#main-content" 
      className="skip-to-content"
      onClick={handleSkip}
    >
      Skip to main content
    </a>
  );
};

export default SkipToContent;
