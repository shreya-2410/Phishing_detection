# Email Phishing Detector Chrome Extension

A Chrome extension that helps users identify potential phishing attempts in their emails using advanced detection techniques and an interactive, user-friendly interface.

## Features

### 🔍 Smart Detection
- Analyzes email content in real-time
- Detects multiple types of phishing indicators:
  - Urgency tactics and pressure language
  - Suspicious links and URL patterns
  - Generic/impersonal greetings
  - Requests for sensitive information
  - Time pressure tactics
  - Potential sender spoofing

### 🎯 Risk Assessment
- Three-level risk classification:
  - 🔴 High Risk - Likely phishing attempts
  - 🟡 Suspicious - Exercise caution
  - 🟢 Low Risk - No obvious red flags

### 💡 Interactive Analysis
- Click on detected issues to highlight them in the email
- Visual badges for different types of threats
- Detailed explanations for each detected issue
- Specific recommendations based on risk level

### 📧 Email Provider Support
- Gmail
- Outlook
- Yahoo Mail
- (More providers coming soon)

## Installation

1. Clone this repository or download the source code
```bash
git clone https://github.com/RohinSequeira/phishing_detection.git
```

2. Open Chrome and navigate to `chrome://extensions/`

3. Enable "Developer mode" in the top right corner

4. Click "Load unpacked" and select the extension directory

5. The extension icon should now appear in your Chrome toolbar

## Usage

1. Open an email in a supported email provider (Gmail, Outlook, or Yahoo Mail)

2. Click the Email Phishing Detector extension icon

3. Click "Scan Current Email"

4. Review the analysis results:
   - Overall risk level
   - Warning badges for specific threats
   - Detailed list of detected issues
   - Click on any issue to highlight it in the email
   - Review recommended actions

## Technical Details

### Files Structure
- `manifest.json` - Extension configuration
- `popup.html` - Extension popup interface
- `popup.js` - Popup functionality and UI handling
- `content.js` - Email analysis and content processing
- `images/` - Extension icons

### Detection Patterns
The extension checks for:
- Suspicious sender domains
- Urgency keywords in subject
- Suspicious URL patterns
- Common phishing phrases
- Generic greetings
- Time pressure tactics
- Requests for sensitive information

## Security Considerations

- The extension runs entirely in your browser
- No email content is sent to external servers
- All analysis is performed locally
- No sensitive information is collected or stored

## Contributing

Contributions are welcome! Here are some ways you can help:

- Report bugs
- Suggest new features
- Add support for more email providers
- Improve detection patterns
- Enhance the user interface

## Future Enhancements

- [ ] Support for more email providers
- [ ] Machine learning-based detection
- [ ] Custom rules configuration
- [ ] Historical analysis tracking
- [ ] Bulk email scanning
- [ ] Integration with known phishing databases
- [ ] Export and reporting features

 
