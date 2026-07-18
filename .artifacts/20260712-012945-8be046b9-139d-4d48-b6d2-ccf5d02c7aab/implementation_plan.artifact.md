# Implementation Plan - Ngabo (Market Ready Phase 1)

This plan outlines the steps to make **Ngabo** a market-ready Android application for mobile money agents in Uganda, focusing on automated transaction tracking, capital protection, and regulatory compliance.

## User Review Required

> [!IMPORTANT]
> - **Notification Listener Permission**: The user will need to manually enable the "Notification Access" in Android settings. I will implement a guide/prompt for this.
> - **Data Privacy**: The app will store all financial data locally. We are committed to an "offline-first" approach for the pilot to ensure maximum privacy and compliance with Uganda's Data Protection Act 2019.

## Proposed Changes

### Native Android Layer
Enhance native capabilities to capture transaction data reliably and future-proof against Google Play Store restrictions.

#### [NEW] [NotificationListenerService.java](file:///C:/Users/LENOVO/Desktop/agent mobile money/android/app/src/main/java/com/ngabo/app/NotificationListenerService.java)
- Implement `NotificationListenerService` to intercept notifications from MTN MoMo and Airtel Money.
- Extract transaction text and sender info.
- Broadcast events to the WebView using `evaluateJavascript` (event name: `nativeNotificationReceived`).

#### [MainActivity.java](file:///C:/Users/LENOVO/Desktop/agent mobile money/android/app/src/main/java/com/ngabo/app/MainActivity.java)
- Add logic to check if Notification Access is granted.
- Provide a button or prompt to open system settings for Notification Access.

#### [AndroidManifest.xml](file:///C:/Users/LENOVO/Desktop/agent mobile money/android/app/src/main/AndroidManifest.xml)
- Register `NotificationListenerService`.
- Add `BIND_NOTIFICATION_LISTENER_SERVICE` permission.

---

### Web Logic Layer (JS)
Refine the core intelligence and compliance features.

#### [app.js](file:///C:/Users/LENOVO/Desktop/agent mobile money/www/app.js)
- Implement `nativeNotificationReceived` listener to handle incoming notifications similarly to the existing `nativeSmsReceived` bridge.
- Refine Regex patterns to match both SMS and Notification formats (which can differ slightly).
- Implement the "Wipe Data" logic to securely clear all preferences and reset the app state.
- Enhance `AIReconciler` with more specific diagnostics based on the latest blueprint.

#### [index.html](file:///C:/Users/LENOVO/Desktop/agent mobile money/www/index.html)
- Ensure the consent screen is the very first thing seen and cannot be bypassed.
- Add a "Privacy Policy" section or link in settings.

---

### UI/UX Refinement
Ensure readability and ease of use in the high-pressure environment of a metal kiosk.

#### [styles.css](file:///C:/Users/LENOVO/Desktop/agent mobile money/www/styles.css)
- Verify high-contrast ratios for direct sunlight readability.
- Ensure buttons are large and hit-targets are generous.

## Verification Plan

### Automated Tests
- I will use `adb shell notification post` to simulate MTN/Airtel transaction notifications and verify they are correctly parsed and recorded in the app's JS database.
- I will simulate fraudulent notifications (e.g., from a regular phone number) to verify the Security Module flags them.

### Manual Verification
- **Onboarding Flow**: Manually walk through the consent, setup, PIN, and scan screens to ensure a smooth "magic onboarding" experience.
- **Money Outside**: Add several loan/credit entries and verify the 6:00 PM reminder triggers correctly.
- **EOD Audit**: Enter mismatched balances and verify the AI Reconciliation Engine provides actionable diagnostics.
- **Data Wipe**: Trigger the wipe data function and verify all local storage is empty upon reload.
