package com.kioskcontrol.app;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.telephony.SmsMessage;
import android.util.Log;

import com.getcapacitor.JSObject;
import com.getcapacitor.PluginCall;

/**
 * SmsBroadcastReceiver
 * ─────────────────────────────────────────────────────────────────────
 * Intercepts every incoming SMS at the Android OS level.
 * Passes the raw (sender, body) pair to the Capacitor bridge where
 * the existing JavaScript Parser module handles classification.
 *
 * Trusted senders watched: MTN (MoMo/MobileMoney), Airtel (AIRTEL/AirtelMoney)
 * ─────────────────────────────────────────────────────────────────────
 */
public class SmsBroadcastReceiver extends BroadcastReceiver {

    private static final String TAG = "KioskControl_SMS";

    // Trusted sender ID whitelist (case-insensitive)
    private static final String[] TRUSTED_SENDERS = {
        "MobileMoney", "MTN", "MTNMOMO", "MoMo",
        "AIRTEL", "AirtelMoney", "Airtel",
        "Centenary", "PostaBank", "STANBIC", "DFCU"
    };

    @Override
    public void onReceive(Context context, Intent intent) {
        if ("android.provider.Telephony.SMS_RECEIVED".equals(intent.getAction())) {
            Bundle bundle = intent.getExtras();
            if (bundle == null) return;

            Object[] pdus = (Object[]) bundle.get("pdus");
            String format   = bundle.getString("format");
            if (pdus == null) return;

            for (Object pdu : pdus) {
                SmsMessage sms = SmsMessage.createFromPdu((byte[]) pdu, format);
                if (sms == null) continue;

                String sender = sms.getDisplayOriginatingAddress();
                String body   = sms.getMessageBody();

                Log.d(TAG, "SMS received from: " + sender);

                // Send to Capacitor bridge via static reference on MainActivity
                if (MainActivity.webView != null) {
                    JSObject payload = new JSObject();
                    payload.put("sender", sender != null ? sender : "UNKNOWN");
                    payload.put("body",   body   != null ? body   : "");
                    payload.put("isTrusted", isTrustedSender(sender));

                    // Fire a JS custom event that our app.js is listening for
                    final String script = "window.dispatchEvent(new CustomEvent('nativeSmsReceived', " +
                        "{ detail: " + payload.toString() + " }));";

                    MainActivity.webView.post(() ->
                        MainActivity.webView.evaluateJavascript(script, null)
                    );

                    Log.d(TAG, "SMS dispatched to JS bridge. Trusted: " + isTrustedSender(sender));
                }
            }
        }
    }

    /**
     * Check if the sender originates from a known, trusted telecom sender ID.
     */
    private boolean isTrustedSender(String sender) {
        if (sender == null) return false;
        String senderUpper = sender.toUpperCase();
        for (String trusted : TRUSTED_SENDERS) {
            if (senderUpper.contains(trusted.toUpperCase())) {
                return true;
            }
        }
        // Also trust short numeric codes (5-6 digit shortcodes used by telecoms)
        if (sender.matches("\\d{5,6}")) return true;
        return false;
    }
}
