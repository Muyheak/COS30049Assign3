// All back-end calls live in this one file.
// FAKE version for now: when the back end is ready, only this
// function changes (to a fetch call to REACT_APP_API_URL).
export async function checkUrl(url) {
    await new Promise((resolve) => setTimeout(resolve, 1000)); // pretend to wait
  
    // Type "fail" in a URL to test the error state.
    if (url.includes('fail')) {
      throw new Error('Could not reach the server. Please try again.');
    }
  
    const looksPhishy = url.includes('login') || url.includes('verify');
    return {
      url,
      label: looksPhishy ? 'phishing' : 'legitimate',
      confidence: looksPhishy ? 0.93 : 0.88,
    };
  }