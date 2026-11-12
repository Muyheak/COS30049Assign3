// All back-end calls live in this one file.

const API_URL = process.env.REACT_APP_API_URL || "http://localhost:8000";

export async function checkUrl(url) {
  let response;
  try {
    response = await fetch(`${API_URL}/api/v1/check`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });
  } catch {
    throw new Error("Could not reach the server. Please try again.");
  }

  if (response.status === 503) {
    throw new Error("Server is busy. Please wait a moment and try again.");
  }
  if (response.status === 429) {
    throw new Error("Too many requests. Please wait a minute and try again.");
  }
  if (response.status === 422) {
    throw new Error("Please enter a valid URL.");
  }
  if (response.status === 413) {
    throw new Error("URL is too long.");
  }
  if (!response.ok) {
    throw new Error("Could not check this URL. Please try again.");
  }

  const data = await response.json();
  return {
    url: data.normalised_url || url,
    label: data.label,       // "phishing" | "legitimate"
    confidence: data.confidence,
  };
}