/**
 * Decode HTML entities and Unicode escapes
 * @param {string} html - HTML string with potential entities and escapes
 * @returns {string} Decoded HTML
 */
export const decodeHtml = (html) => {
  if (!html) return '';
  
  // Create a temporary element to decode HTML entities
  const txt = document.createElement('textarea');
  txt.innerHTML = html;
  let decoded = txt.value;
  
  // Decode Unicode escapes like \u2019
  try {
    decoded = decoded.replace(/\\u[\dA-F]{4}/gi, (match) => {
      return String.fromCharCode(parseInt(match.replace(/\\u/g, ''), 16));
    });
  } catch (e) {
    console.warn('Failed to decode Unicode escapes:', e);
  }
  
  return decoded;
};

/**
 * Render HTML string safely
 * @param {string} html - HTML string to render
 * @returns {Object} Props for dangerouslySetInnerHTML
 */
export const renderHtml = (html) => {
  return { __html: decodeHtml(html) };
};
