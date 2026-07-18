package com.ngabo.app;

import android.service.notification.NotificationListenerService;
import android.service.notification.StatusBarNotification;
import android.util.Log;
import com.getcapacitor.JSObject;

/**
 * NotificationListenerService — Ngabo
 * ─────────────────────────────────────────────────────────────────────
 * Intercepts incoming system notifications from MTN and Airtel.
 * Extracts the transaction text and broadcasts it to the WebView
 * using evaluateJavascript.
 * ─────────────────────────────────────────────────────────────────────
 */
public class NotificationListenerService extends android.service.notification.NotificationListenerService {

    private static final String TAG = "Ngabo_Notification";

    @Override
    public void onNotificationPosted(StatusBarNotification sbn) {
        String packageName = sbn.getPackageName();
        if (packageName == null) return;

        // Watch for MTN and Airtel notification packages
        // Common package patterns for MoMo apps and system alerts
        if (packageName.contains("mtn") || packageName.contains("airtel") || 
            packageName.contains("telecom") || packageName.contains("momo")) {

            if (sbn.getNotification().extras != null) {
                CharSequence title = sbn.getNotification().extras.getCharSequence("android.title");
                CharSequence text = sbn.getNotification().extras.getCharSequence("android.text");

                if (text != null) {
                    Log.d(TAG, "Notification intercepted from: " + packageName);
                    broadcastToWebView(packageName, title != null ? title.toString() : "Unknown", text.toString());
                }
            }
        }
    }

    private void broadcastToWebView(String packageName, String title, String text) {
        if (MainActivity.webView == null) return;

        JSObject payload = new JSObject();
        payload.put("packageName", packageName);
        payload.put("title", title);
        payload.put("body", text);
        payload.put("timestamp", System.currentTimeMillis());

        // Fire a custom event 'nativeNotificationReceived' in the WebView
        final String script = "window.dispatchEvent(new CustomEvent('nativeNotificationReceived', " +
                "{ detail: " + payload.toString() + " }));";

        MainActivity.webView.post(() -> {
            MainActivity.webView.evaluateJavascript(script, null);
            Log.d(TAG, "Notification broadcasted to JS bridge.");
        });
    }

    @Override
    public void onNotificationRemoved(StatusBarNotification sbn) {
        // Not needed for current implementation
    }
}
