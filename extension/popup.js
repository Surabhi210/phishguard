document.addEventListener('DOMContentLoaded', () => {
  grabSelectedText();

  document.getElementById('grabBtn').addEventListener('click', grabSelectedText);
  document.getElementById('analyzeBtn').addEventListener('click', analyzeText);
});

window.scrapedData = null;

async function grabSelectedText() {
  const textInput = document.getElementById('textInput');
  const resultsBox = document.getElementById('resultsBox');
  const errorBox = document.getElementById('errorBox');
  
  // Clear previous output
  errorBox.style.display = 'none';
  resultsBox.style.display = 'none';
  window.scrapedData = null;

  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab) return;
    
    chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: () => {
        const selection = window.getSelection().toString().trim();
        if (selection) {
          return { type: 'selection', text: selection };
        }
        
        // Scrape Gmail elements if open
        if (window.location.host === 'mail.google.com') {
          const subjectEl = document.querySelector('h1.hP');
          const bodyEl = document.querySelector('.a3s.aiL') || document.querySelector('.a3s') || document.querySelector('.ii.gt');
          const senderEl = document.querySelector('.gD');
          
          if (subjectEl || bodyEl || senderEl) {
            return {
              type: 'gmail',
              subject: subjectEl ? subjectEl.innerText.trim() : '',
              body: bodyEl ? bodyEl.innerText.trim() : '',
              sender: senderEl ? (senderEl.getAttribute('email') || senderEl.innerText.trim()) : ''
            };
          }
        }
        return { type: 'none' };
      }
    }, (results) => {
      if (results && results[0] && results[0].result) {
        const res = results[0].result;
        if (res.type === 'selection') {
          textInput.value = res.text;
          textInput.placeholder = "Pasted or selected text...";
        } else if (res.type === 'gmail') {
          window.scrapedData = res;
          textInput.value = `From: ${res.sender}\nSubject: ${res.subject}\n\n${res.body}`;
          // Automatically trigger analysis for Gmail emails!
          analyzeText();
        } else {
          textInput.value = '';
          textInput.placeholder = "Select text on the webpage, or paste email body content here...";
        }
      }
    });
  } catch (err) {
    console.log('Selection/DOM grab not available:', err);
  }
}

async function analyzeText() {
  const text = document.getElementById('textInput').value.trim();
  const errorBox = document.getElementById('errorBox');
  const resultsBox = document.getElementById('resultsBox');
  const btnLabel = document.getElementById('btnLabel');
  const spinner = document.getElementById('spinner');
  const analyzeBtn = document.getElementById('analyzeBtn');

  if (!text) {
    showError('Please paste some text, highlight text, or open an email in Gmail.');
    return;
  }

  // Clear previous output
  errorBox.style.display = 'none';
  resultsBox.style.display = 'none';
  
  // Loading state
  btnLabel.textContent = 'Scanning...';
  spinner.style.display = 'block';
  analyzeBtn.disabled = true;

  try {
    let payload = {
      sender: '',
      subject: '',
      body: text
    };

    // If we have parsed Gmail components, use them
    if (window.scrapedData) {
      payload.sender = window.scrapedData.sender || '';
      payload.subject = window.scrapedData.subject || '';
      payload.body = window.scrapedData.body || '';
    }

    const response = await fetch('http://127.0.0.1:5000/analyze', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(payload)
    });

    if (!response.ok) {
      throw new Error(`Server returned status code ${response.status}`);
    }

    const data = await response.json();
    if (data.error) throw new Error(data.error);

    renderResults(data);

  } catch (err) {
    showError(err.message || 'Could not reach the scan server. Make sure Flask is running on http://127.0.0.1:5000.');
  } finally {
    btnLabel.textContent = '🔍 Analyze Content';
    spinner.style.display = 'none';
    analyzeBtn.disabled = false;
  }
}

function renderResults(data) {
  const resultsBox = document.getElementById('resultsBox');
  const verdictCard = document.getElementById('verdictCard');
  const verdictEmoji = document.getElementById('verdictEmoji');
  const verdictTitle = document.getElementById('verdictTitle');
  const verdictSubtitle = document.getElementById('verdictSubtitle');
  const scoreVal = document.getElementById('scoreVal');

  const isPhish = data.prediction === 1;
  
  // Update Verdict UI
  verdictCard.className = 'verdict-card ' + (isPhish ? 'phish' : 'safe');
  verdictEmoji.textContent = isPhish ? '🚨' : '✅';
  verdictTitle.textContent = isPhish ? 'Phishing Email' : 'Looks Safe';
  
  // Create subtitles showing sender/domain info if available
  let subtitleText = '';
  if (data.sender_reputation) {
    const rep = data.sender_reputation;
    if (rep.status === 'Malicious') {
      subtitleText = `Sender domain [${rep.domain}] is malicious!`;
    } else if (rep.status === 'Safe') {
      subtitleText = `Sender domain is verified: Safe.`;
    } else if (rep.status === 'Unknown' || rep.status === 'Unknown Domain') {
      subtitleText = `No sender reputation data available for [${rep.domain}].`;
    } else {
      subtitleText = `Sender domain status: ${rep.status}.`;
    }
  } else {
    subtitleText = isPhish ? 'High threat signals detected.' : 'No strong threat patterns found.';
  }
  verdictSubtitle.textContent = subtitleText;
  
  // Update Score
  scoreVal.textContent = `${data.threat_score}/100`;
  const color = data.threat_score <= 30 ? '#23D18B' : data.threat_score <= 65 ? '#F0A832' : '#F04747';
  scoreVal.style.color = color;

  resultsBox.style.display = 'block';
}

function showError(msg) {
  const errorBox = document.getElementById('errorBox');
  errorBox.textContent = `⚠ ${msg}`;
  errorBox.style.display = 'block';
}
