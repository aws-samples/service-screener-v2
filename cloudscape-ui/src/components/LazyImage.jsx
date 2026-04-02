import React, { useState, useRef, useEffect } from 'react';
import Spinner from '@cloudscape-design/components/spinner';
import Box from '@cloudscape-design/components/box';

/**
 * LazyImage Component
 * 
 * Implements lazy loading for images with responsive design and performance optimization.
 * IMPORTANT: Only works with pre-embedded image data from Python backend.
 * No external image fetching - maintains complete offline compatibility with file:// protocol.
 * 
 * Features:
 * - Intersection Observer API for lazy loading of pre-embedded images
 * - Responsive image sources for different screen densities (pre-processed by Python)
 * - Loading states with skeleton placeholders
 * - Error handling with fallback images (all pre-embedded)
 * - Performance monitoring for embedded images only
 */
const LazyImage = ({
  src,
  alt,
  className = '',
  style = {},
  responsiveSources = {},
  loadingStrategy = 'lazy',
  rootMargin = '50px',
  threshold = 0.1,
  onLoad = () => {},
  onError = () => {},
  onLoadStart = () => {},
  fallbackSrc = null,
  showLoadingIndicator = true,
  skeletonHeight = 200,
  maxRetries = 2
}) => {
  const [isLoaded, setIsLoaded] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [hasError, setHasError] = useState(false);
  const [currentSrc, setCurrentSrc] = useState(loadingStrategy === 'eager' ? src : null);
  const [retryCount, setRetryCount] = useState(0);
  const [loadStartTime, setLoadStartTime] = useState(null);
  
  const imgRef = useRef(null);
  const observerRef = useRef(null);

  // Get responsive source based on device pixel ratio and viewport width
  // IMPORTANT: All sources must be pre-embedded by Python backend
  const getResponsiveSource = () => {
    if (!responsiveSources || Object.keys(responsiveSources).length === 0) {
      return src; // Use original src if no responsive sources provided
    }

    const devicePixelRatio = window.devicePixelRatio || 1;
    const viewportWidth = window.innerWidth;

    // Check for density-based sources (pre-processed by Python)
    if (responsiveSources.density_sources) {
      const densityKey = devicePixelRatio >= 2 ? '2x' : '1x';
      if (responsiveSources.density_sources[densityKey]) {
        return responsiveSources.density_sources[densityKey];
      }
    }

    // Check for size-based sources (pre-processed by Python)
    if (responsiveSources.size_sources) {
      let selectedSource = src;
      
      if (viewportWidth < 768 && responsiveSources.size_sources.small) {
        selectedSource = responsiveSources.size_sources.small.src;
      } else if (viewportWidth < 1024 && responsiveSources.size_sources.medium) {
        selectedSource = responsiveSources.size_sources.medium.src;
      } else if (responsiveSources.size_sources.large) {
        selectedSource = responsiveSources.size_sources.large.src;
      }

      return selectedSource;
    }

    return src; // Fallback to original src
  };

  // Handle image load success
  const handleImageLoad = (event) => {
    const loadEndTime = performance.now();
    const loadDuration = loadStartTime ? loadEndTime - loadStartTime : 0;

    setIsLoaded(true);
    setIsLoading(false);
    setHasError(false);

    // Call external load handler with performance metrics
    onLoad({
      src: currentSrc,
      loadDuration,
      retryCount,
      naturalWidth: event.target.naturalWidth,
      naturalHeight: event.target.naturalHeight
    });
  };

  // Handle image load error with retry logic
  // IMPORTANT: Only retries with pre-embedded fallback sources
  const handleImageError = (event) => {
    console.warn(`Failed to load pre-embedded image: ${currentSrc}`);

    if (retryCount < maxRetries && fallbackSrc) {
      // Only retry if we have a pre-embedded fallback source
      setTimeout(() => {
        setRetryCount(prev => prev + 1);
        setHasError(false);
        setIsLoading(true);
        setLoadStartTime(performance.now());
        
        // Use pre-embedded fallback source (no cache-busting needed for embedded images)
        setCurrentSrc(fallbackSrc);
      }, 1000 * (retryCount + 1)); // Exponential backoff
    } else {
      // Max retries reached or no fallback available, show error state
      setIsLoading(false);
      setHasError(true);
    }

    onError({
      src: currentSrc,
      retryCount,
      error: event.error || 'Pre-embedded image load failed'
    });
  };

  // Handle image load start
  const handleImageLoadStart = () => {
    setIsLoading(true);
    setLoadStartTime(performance.now());
    onLoadStart({ src: currentSrc });
  };

  // Intersection Observer setup for lazy loading
  useEffect(() => {
    if (loadingStrategy === 'eager' || !imgRef.current) {
      return;
    }

    const observerOptions = {
      root: null,
      rootMargin,
      threshold
    };

    observerRef.current = new IntersectionObserver((entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting && !currentSrc) {
          // Image is in viewport, start loading
          const responsiveSrc = getResponsiveSource();
          setCurrentSrc(responsiveSrc);
          setIsLoading(true);
          setLoadStartTime(performance.now());

          // Stop observing once we start loading
          if (observerRef.current) {
            observerRef.current.unobserve(entry.target);
          }
        }
      });
    }, observerOptions);

    if (imgRef.current) {
      observerRef.current.observe(imgRef.current);
    }

    return () => {
      if (observerRef.current) {
        observerRef.current.disconnect();
      }
    };
  }, [loadingStrategy, rootMargin, threshold, currentSrc]);

  // Handle responsive source changes on window resize
  useEffect(() => {
    if (!currentSrc || loadingStrategy === 'eager') return;

    const handleResize = () => {
      const newSrc = getResponsiveSource();
      if (newSrc !== currentSrc && !isLoading) {
        setCurrentSrc(newSrc);
        setIsLoaded(false);
        setIsLoading(true);
        setLoadStartTime(performance.now());
      }
    };

    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, [currentSrc, isLoading, loadingStrategy]);

  // Render loading skeleton
  const renderLoadingSkeleton = () => {
    if (!showLoadingIndicator) return null;

    return (
      <div
        style={{
          width: '100%',
          height: skeletonHeight,
          backgroundColor: '#f0f0f0',
          borderRadius: '4px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          animation: 'pulse 1.5s ease-in-out infinite',
          ...style
        }}
        className={className}
      >
        <div style={{ textAlign: 'center' }}>
          <Spinner size="normal" />
          <Box variant="small" color="text-body-secondary" margin={{ top: 's' }}>
            Loading image...
          </Box>
        </div>
      </div>
    );
  };

  // Render error state
  const renderErrorState = () => {
    return (
      <div
        style={{
          width: '100%',
          height: skeletonHeight,
          backgroundColor: '#fafafa',
          border: '1px dashed #d1d5db',
          borderRadius: '4px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          ...style
        }}
        className={className}
      >
        <div style={{ textAlign: 'center', padding: '16px' }}>
          <Box variant="small" color="text-body-secondary">
            📷 Image unavailable
          </Box>
          {retryCount > 0 && (
            <Box variant="small" color="text-body-secondary" margin={{ top: 'xs' }}>
              (Retried {retryCount} times)
            </Box>
          )}
        </div>
      </div>
    );
  };

  // Render placeholder for lazy loading
  if (!currentSrc && loadingStrategy === 'lazy') {
    return (
      <div
        ref={imgRef}
        style={{
          width: '100%',
          height: skeletonHeight,
          backgroundColor: '#f8f9fa',
          borderRadius: '4px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          ...style
        }}
        className={className}
      >
        <Box variant="small" color="text-body-secondary">
          📷 Image will load when visible
        </Box>
      </div>
    );
  }

  // Show loading state
  if (isLoading && !isLoaded) {
    return renderLoadingSkeleton();
  }

  // Show error state
  if (hasError && !fallbackSrc) {
    return renderErrorState();
  }

  // Render the actual image
  return (
    <img
      ref={imgRef}
      src={currentSrc}
      alt={alt}
      className={className}
      style={{
        opacity: isLoaded ? 1 : 0,
        transition: 'opacity 0.3s ease-in-out',
        ...style
      }}
      onLoad={handleImageLoad}
      onError={handleImageError}
      onLoadStart={handleImageLoadStart}
      loading={loadingStrategy}
      decoding="async"
      // Add responsive image attributes
      sizes={responsiveSources.size_sources ? 
        "(max-width: 768px) 100vw, (max-width: 1024px) 50vw, 33vw" : 
        undefined
      }
    />
  );
};

// Add CSS for pulse animation
const style = document.createElement('style');
style.textContent = `
  @keyframes pulse {
    0%, 100% {
      opacity: 1;
    }
    50% {
      opacity: 0.5;
    }
  }
`;
document.head.appendChild(style);

export default LazyImage;