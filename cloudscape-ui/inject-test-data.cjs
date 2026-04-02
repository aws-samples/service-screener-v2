const fs = require('fs');

// Read the HTML file
const html = fs.readFileSync('dist/test.html', 'utf8');

// Read the test data
const testData = fs.readFileSync('test-data.json', 'utf8');

// Create the data injection script
const dataScript = `<script>window.__REPORT_DATA__ = ${testData};</script>`;

// Inject the script before the closing </head> tag
const modifiedHtml = html.replace('</head>', `${dataScript}\n</head>`);

// Write the modified HTML
fs.writeFileSync('dist/test.html', modifiedHtml);

console.log('Test data injected successfully!');
