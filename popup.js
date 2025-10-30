document.addEventListener('DOMContentLoaded', function() {
    const scanBtn = document.getElementById('scanBtn');
    const results = document.getElementById('results');
    const loading = document.getElementById('loading');
    const riskLevel = document.getElementById('riskLevel');
    const details = document.getElementById('details');
    const errorMessage = document.getElementById('errorMessage');
    const warningBadges = document.getElementById('warningBadges');
    const recommendationsList = document.getElementById('recommendationsList');

    scanBtn.addEventListener('click', async () => {
        // Reset UI
        loading.style.display = 'block';
        results.style.display = 'none';
        errorMessage.style.display = 'none';
        scanBtn.disabled = true;

        try {
            // Get the active tab
            const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
            
            // Check if we're on a supported email domain
            const supportedDomains = [
                'mail.google.com',
                'outlook.live.com',
                'outlook.office.com',
                'mail.yahoo.com'
            ];
            
            const url = new URL(tab.url);
            if (!supportedDomains.includes(url.hostname)) {
                throw new Error('Please open an email in Gmail, Outlook, or Yahoo Mail to scan.');
            }

            // Execute content script
            const response = await new Promise((resolve, reject) => {
                chrome.tabs.sendMessage(tab.id, { action: "getEmailContent" }, (response) => {
                    if (chrome.runtime.lastError) {
                        reject(new Error(chrome.runtime.lastError.message));
                        return;
                    }
                    if (!response) {
                        reject(new Error('Empty response from content script'));
                        return;
                    }
                    resolve(response);
                });
            });

            console.log('Received analysis from content script:', response);
            
            // Update UI with results
            displayResults(response);
        } catch (error) {
            console.error('Error:', error);
            errorMessage.textContent = error.message || 'Error analyzing email. Please try again.';
            errorMessage.style.display = 'block';
            results.style.display = 'none';
        } finally {
            loading.style.display = 'none';
            scanBtn.disabled = false;
        }
    });

    async function highlightIssue(text, location) {
        try {
            const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
            await chrome.tabs.sendMessage(tab.id, {
                action: "highlightText",
                text: text,
                location: location
            });
        } catch (error) {
            console.error('Error highlighting text:', error);
        }
    }

    function createClickableListItem(issue) {
        const li = document.createElement('li');
        li.textContent = issue.detail;
        li.style.cursor = 'pointer';
        li.style.padding = '5px';
        li.style.marginBottom = '5px';
        li.style.borderRadius = '4px';
        li.style.transition = 'background-color 0.2s';
        
        // Add hover effect
        li.addEventListener('mouseenter', () => {
            li.style.backgroundColor = '#f0f0f0';
        });
        
        li.addEventListener('mouseleave', () => {
            li.style.backgroundColor = 'transparent';
        });

        // Add click handler
        if (issue.text && issue.location) {
            li.addEventListener('click', () => {
                highlightIssue(issue.text, issue.location);
            });
            
            // Add visual indicator that this is clickable
            li.innerHTML += ' <span style="color: #6c5ce7; font-size: 12px;">(click to highlight)</span>';
        }

        return li;
    }

    function displayResults(analysis) {
        results.style.display = 'block';
        
        // Hide all badges initially
        warningBadges.querySelectorAll('.badge').forEach(badge => {
            badge.style.display = 'none';
        });

        // Determine risk level and set appropriate warnings
        let riskClass = '';
        let riskText = '';
        let recommendations = [];
        let activeBadges = new Set();

        // Collect all warning types from both high risk factors and warnings
        if (analysis.highRiskFactors) {
            analysis.highRiskFactors.forEach(factor => {
                activeBadges.add(factor.type);
            });
        }
        if (analysis.warnings) {
            analysis.warnings.forEach(warning => {
                activeBadges.add(warning.type);
            });
        }

        // Show only relevant badges
        activeBadges.forEach(type => {
            const badge = warningBadges.querySelector(`[data-type="${type}"]`);
            if (badge) {
                badge.style.display = 'flex';
                badge.classList.add('active');
            }
        });

        // Set risk level and recommendations
        if (analysis.highRiskFactors && analysis.highRiskFactors.length > 0) {
            riskClass = 'high-risk';
            riskText = '🔴 High Risk - Likely Phishing Attempt';
            recommendations = [
                'Do not click any links in this email',
                'Do not download any attachments',
                'Do not reply to this email',
                'Report this email as phishing'
            ];
        } else if (analysis.warnings && analysis.warnings.length > 0) {
            riskClass = 'suspicious';
            riskText = '🟡 Suspicious - Exercise Caution';
            recommendations = [
                'Verify the sender through other means',
                'Do not provide sensitive information',
                'When in doubt, contact the company directly'
            ];
        } else {
            riskClass = 'low-risk';
            riskText = '🟢 Low Risk - No Obvious Red Flags';
            recommendations = [
                'Always remain vigilant with email communications',
                'Keep your security software up to date'
            ];
        }

        // Set risk level
        riskLevel.className = `risk-level ${riskClass}`;
        riskLevel.textContent = riskText;

        // Display details with clickable items
        if ((analysis.highRiskFactors && analysis.highRiskFactors.length > 0) || 
            (analysis.warnings && analysis.warnings.length > 0)) {
            const detailsList = document.createElement('ul');
            detailsList.style.listStyle = 'none';
            detailsList.style.padding = '0';

            // Add high risk factors
            if (analysis.highRiskFactors) {
                analysis.highRiskFactors.forEach(factor => {
                    detailsList.appendChild(createClickableListItem(factor));
                });
            }

            // Add warnings
            if (analysis.warnings) {
                analysis.warnings.forEach(warning => {
                    detailsList.appendChild(createClickableListItem(warning));
                });
            }

            details.innerHTML = '<h3>Detected Issues:</h3>';
            details.appendChild(detailsList);
        } else {
            details.innerHTML = '<p>No suspicious elements detected.</p>';
        }

        // Display recommendations
        recommendationsList.innerHTML = recommendations.map(rec => `<li>${rec}</li>`).join('');

        // Show warning badges section only if there are active badges
        warningBadges.style.display = activeBadges.size > 0 ? 'flex' : 'none';
    }
}); 