// All back-end calls live in this one file.

const API_URL = process.env.REACT_APP_API_URL || "http://127.0.0.1:8000";

export async function checkUrl(url) {
  let response;
  try {
    response = await fetch(`${API_URL}/predict`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });
  } catch (networkErr) {
    throw new Error("Could not reach the server, please try again.");
  }

  if (response.status === 429) {
    throw new Error("Too many requests, please wait a minute and try again.");
  }

  if (response.status === 422) {
    throw new Error("Please enter a valid URL.");
  }

  if (!response.ok) {
    throw new Error("Could not check this URL, please try again.");
  }

  const data = await response.json();
  return {
    url,
    label: data.label === "1" ? "phishing" : "legitimate",
    confidence: data.confidence,
  };
}