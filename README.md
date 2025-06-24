# zoom-rtms-demo

---

# Zoom Real-Time Media Streams (RTMS) and AI Translation Example

This repository contains a Node.js application demonstrating how to leverage Zoom's Real-Time Media Streams (RTMS) to capture live meeting transcripts and translate them in real-time using an AI translation module.

-----

## Features

  * **Zoom OAuth Integration:** Securely authenticates with Zoom for API access.
  * **Webhook Listener:** Responds to Zoom webhook events, including `meeting.rtms_started` and `meeting.rtms_stopped`.
  * **Real-Time Transcript Capture:** Connects to Zoom's Media WebSocket to receive live meeting transcripts.
  * **AI-Powered Translation:** Integrates with a translation library to translate incoming English transcripts to Spanish.
  * **Local Transcript Storage:** Appends translated transcripts to a `sample.txt` file.
  * **Web Interface:** A simple `/home` route displays the real-time translated transcript from `sample.txt`.

-----

## Getting Started

### Prerequisites

  * Node.js (v14 or higher recommended)
  * An ngrok account (or similar tunneling service) for exposing your local development server to the internet.
  * A Zoom Developer Account and a Zoom App configured with:
      * **OAuth:** Enabled with a Redirect URL pointing to your ngrok URL + `/callback` (e.g., `https://your-ngrok-url.ngrok-free.app/callback`).
      * **Scopes:** `user:read`, `meeting:read`, `meeting:write`.
      * **Webhook Subscription:** Subscribe to `meeting.rtms_started` and `meeting.rtms_stopped` events. The Webhook URL should point to your ngrok URL + `/webhook` (e.g., `https://your-ngrok-url.ngrok-free.app/webhook`).
      * **Real-Time Media Streams:** Enabled for your app.

### Installation

1.  **Clone the repository:**

    ```bash
    git clone <repository-url>
    cd <repository-directory>
    ```

2.  **Install dependencies:**

    ```bash
    npm install
    ```

3.  **Configure environment variables:**
    Rename `.env.example` to `.env` and update the following:

    ```
    CLIENT_ID=YOUR_ZOOM_CLIENT_ID
    CLIENT_SECRET=YOUR_ZOOM_CLIENT_SECRET
    REDIRECT_URI=YOUR_NGROK_HTTPS_URL/callback
    ZOOM_SECRET_TOKEN=YOUR_ZOOM_WEBHOOK_SECRET_TOKEN
    ```

      * `CLIENT_ID` and `CLIENT_SECRET`: Obtain these from your Zoom App credentials.
      * `REDIRECT_URI`: This should be your ngrok HTTPS URL followed by `/callback`. **Ensure this matches the Redirect URL configured in your Zoom App.**
      * `ZOOM_SECRET_TOKEN`: This is the "Webhook Secret Token" found in your Zoom App's Webhook Subscription settings.

### Running the Application

1.  **Start ngrok (or your tunneling service):**

    ```bash
    ngrok http 3000
    ```

    Make sure to use the HTTPS URL provided by ngrok for your `REDIRECT_URI` and webhook URL in the Zoom App configuration.

2.  **Start the Node.js application:**

    ```bash
    npm start
    ```

3.  **Authorize your Zoom App:**
    Open your browser and navigate to `http://localhost:3000/auth`. This will redirect you to Zoom's authorization page. Grant access to your app. After successful authorization, you will be redirected to `http://localhost:3000/callback` showing your user information.

4.  **Access the Home Page:**
    Navigate to `http://localhost:3000/home` to view the live translated transcripts. Initially, it will show "Loading..." until RTMS data is received.

### Testing Real-Time Transcripts

1.  **Start a Zoom Meeting:** Ensure you are logged into Zoom with the same account that authorized the application.
2.  **Enable Live Transcription:** In your Zoom meeting, ensure live transcription is enabled.
3.  **Speak in the Meeting:** As you speak in the meeting, the application will receive the transcript data, translate it, and update the `sample.txt` file, which will then be displayed on the `/home` page.

### Expected Output

```
Media JSON Message: {
  "content": {
    "attribute": 1,
    "data": "Hello! Hello!",
    "language": 9,
    "timestamp": 1750791055005605,
    "user_id": 16778240,
    "user_name": "Fabian Valle"
  },
  "msg_type": 17
}
Received signaling message: {
  event: { event_type: 1, media_type: 8, timestamp: 1750791055005605 },
  msg_type: 6
}
Translated text: ¡Hola! ¡Hola!
Appended transcript to sample.txt: ¡Hola! ¡Hola!

```

-----

## Important Notes

  * **Security:** This is a sample application. For production environments, consider more robust security measures, including secure storage of tokens, advanced error handling, and comprehensive logging.
  * **`sample.txt`:** The `sample.txt` file is used for demonstration purposes. In a production scenario, you would typically store transcripts in a database or stream them to another service.
  * **`translate` Module:** This example uses the `translate` npm package. Ensure you have the necessary API keys or configurations if you are using a cloud-based translation service.
  * **Webhook Validation:** The `/webhook` endpoint includes basic validation for Zoom's URL validation challenge.

-----
