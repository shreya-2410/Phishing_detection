// Function to extract email content based on the email provider
function extractEmailContent() {
    let emailContent = {
        subject: '',
        body: '',
        sender: '',
        links: [],
        bodyElement: null // Store reference to body element
    };

    console.log('Starting email content extraction...');
    console.log('Current hostname:', window.location.hostname);

    // Gmail
    if (window.location.hostname.includes('mail.google.com')) {
        // Get email subject
        const subjectElement = document.querySelector('h2.hP');
        console.log('Subject element found:', subjectElement);
        if (subjectElement) {
            emailContent.subject = subjectElement.textContent.trim();
            console.log('Extracted subject:', emailContent.subject);
        }

        // Get email body - try multiple selectors
        const bodySelectors = ['.a3s.aiL', '.a3s.aiL .ii.gt', '.ii.gt'];
        
        for (const selector of bodySelectors) {
            emailContent.bodyElement = document.querySelector(selector);
            if (emailContent.bodyElement) {
                console.log('Found body element with selector:', selector);
                break;
            }
        }

        if (emailContent.bodyElement) {
            emailContent.body = emailContent.bodyElement.innerText.trim();
            console.log('Extracted body:', emailContent.body);
        } else {
            console.log('No body element found with any selector');
        }

        // Get sender - try multiple selectors
        const senderSelectors = ['.gD', '.go', '[email]', '.from'];
        let senderElement = null;

        for (const selector of senderSelectors) {
            senderElement = document.querySelector(selector);
            if (senderElement) {
                console.log('Found sender element with selector:', selector);
                break;
            }
        }

        if (senderElement) {
            emailContent.sender = senderElement.getAttribute('email') || senderElement.textContent.trim();
            console.log('Extracted sender:', emailContent.sender);
        }

        // Get all links
        if (emailContent.bodyElement) {
            const links = emailContent.bodyElement.querySelectorAll('a');
            console.log('Found links:', links.length);
            links.forEach(link => {
                if (link.href && !link.href.startsWith('mailto:')) {
                    emailContent.links.push({
                        url: link.href,
                        element: link
                    });
                    console.log('Added link:', link.href);
                }
            });
        }
    }

    return emailContent;
}

// Function to find and highlight text
function findAndHighlightText(text, element) {
    if (!element || !text) return null;
    
    const range = document.createRange();
    const walker = document.createTreeWalker(
        element,
        NodeFilter.SHOW_TEXT,
        null,
        false
    );

    let node;
    while (node = walker.nextNode()) {
        const position = node.textContent.toLowerCase().indexOf(text.toLowerCase());
        if (position !== -1) {
            range.setStart(node, position);
            range.setEnd(node, position + text.length);
            return range;
        }
    }
    return null;
}

// Function to handle highlighting
function highlightRange(range) {
    // Remove any existing highlights
    document.querySelectorAll('.phishing-highlight').forEach(el => {
        const parent = el.parentNode;
        parent.replaceChild(document.createTextNode(el.textContent), el);
        parent.normalize();
    });

    if (range) {
        const highlight = document.createElement('span');
        highlight.className = 'phishing-highlight';
        highlight.style.backgroundColor = '#ffd700';
        highlight.style.padding = '2px';
        highlight.style.borderRadius = '3px';
        range.surroundContents(highlight);

        // Scroll the highlight into view
        highlight.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
}

// New risk-based analysis
function analyzeEmail(emailContent) {
    let highRiskFactors = [];
    let warnings = [];
    let details = [];

    // Check for high-risk factors
    if (emailContent.subject) {
        const subjectLower = emailContent.subject.toLowerCase();
        const highRiskSubjectPatterns = [
            'account.*suspended',
            'security.*breach',
            'unauthorized.*access',
            'immediate.*action.*required',
            'verify.*account.*now'
        ];

        highRiskSubjectPatterns.forEach(pattern => {
            const regex = new RegExp(pattern);
            const match = subjectLower.match(regex);
            if (match) {
                highRiskFactors.push({
                    type: 'urgency',
                    detail: `Urgent action demanded in subject: "${emailContent.subject}"`,
                    text: match[0],
                    location: 'subject'
                });
            }
        });
    }

    // Check for suspicious sender
    if (emailContent.sender) {
        const senderLower = emailContent.sender.toLowerCase();
        const suspiciousSenderPatterns = [
            '@.*\\.temp\\.',
            '@.*\\.fake\\.',
            '@.*\\.free\\.',
            'noreply@',
            'account@',
            'security@',
            'support@'
        ];

        suspiciousSenderPatterns.forEach(pattern => {
            if (senderLower.match(new RegExp(pattern))) {
                warnings.push({
                    type: 'spoofing',
                    detail: 'Potentially spoofed sender address'
                });
            }
        });
    }

    // Check body content
    if (emailContent.body) {
        const bodyLower = emailContent.body.toLowerCase();

        // Check for sensitive information requests
        const sensitiveInfoPatterns = [
            'password',
            'credit card',
            'social security',
            'bank account',
            'verify.*identity',
            'confirm.*account'
        ];

        sensitiveInfoPatterns.forEach(pattern => {
            const regex = new RegExp(pattern, 'i');
            const match = emailContent.body.match(regex);
            if (match) {
                highRiskFactors.push({
                    type: 'sensitive',
                    detail: `Requests for sensitive information: "${match[0]}"`,
                    text: match[0],
                    location: 'body'
                });
            }
        });

        // Check for urgency/pressure tactics
        const pressurePatterns = [
            'within.*24 hours',
            'account.*suspended',
            'limited time',
            'immediate action',
            'urgent',
            'expires soon'
        ];

        pressurePatterns.forEach(pattern => {
            const regex = new RegExp(pattern, 'i');
            const match = emailContent.body.match(regex);
            if (match) {
                warnings.push({
                    type: 'pressure',
                    detail: `Time pressure tactic: "${match[0]}"`,
                    text: match[0],
                    location: 'body'
                });
            }
        });

        // Check for generic greetings
        const genericGreetings = [
            'dear user',
            'dear customer',
            'dear account holder',
            'dear sir/madam'
        ];

        genericGreetings.forEach(greeting => {
            if (bodyLower.includes(greeting)) {
                warnings.push({
                    type: 'generic',
                    detail: `Generic greeting: "${greeting}"`,
                    text: greeting,
                    location: 'body'
                });
            }
        });
    }

    // Check links
    if (emailContent.links.length > 0) {
        const suspiciousUrlPatterns = [
            'bit\\.ly',
            'tinyurl',
            'goo\\.gl',
            'tiny\\.cc',
            'click\\.here',
            'verify.*account',
            'login.*secure'
        ];

        emailContent.links.forEach(link => {
            const linkLower = link.url.toLowerCase();
            suspiciousUrlPatterns.forEach(pattern => {
                if (linkLower.match(new RegExp(pattern))) {
                    highRiskFactors.push({
                        type: 'links',
                        detail: `Suspicious URL: ${link.url}`,
                        element: link.element,
                        location: 'link'
                    });
                }
            });
        });
    }

    // Store the body element reference for highlighting
    const bodyElement = emailContent.bodyElement;
    delete emailContent.bodyElement; // Remove it from the response

    return {
        highRiskFactors,
        warnings,
        bodyElement: bodyElement
    };
}

// Listen for messages from the popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    console.log('Received message:', request);
    
    if (request.action === "getEmailContent") {
        try {
            console.log('Getting email content...');
            const emailContent = extractEmailContent();
            console.log('Analyzing email content...');
            const analysis = analyzeEmail(emailContent);
            console.log('Analysis complete:', analysis);
            sendResponse(analysis);
        } catch (error) {
            console.error('Error in content script:', error);
            sendResponse({ error: error.message });
        }
    } else if (request.action === "highlightText") {
        try {
            const { text, location } = request;
            let range = null;
            
            if (location === 'subject') {
                const subjectElement = document.querySelector('h2.hP');
                range = findAndHighlightText(text, subjectElement);
            } else if (location === 'body') {
                const bodyElement = document.querySelector('.a3s.aiL');
                range = findAndHighlightText(text, bodyElement);
            }
            
            if (range) {
                highlightRange(range);
                sendResponse({ success: true });
            } else {
                sendResponse({ success: false, error: 'Text not found' });
            }
        } catch (error) {
            console.error('Error highlighting text:', error);
            sendResponse({ success: false, error: error.message });
        }
    }
    return true;
}); 