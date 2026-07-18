package com.ngabo.app;

import android.Manifest;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.ComponentName;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.provider.Settings;
import android.text.TextUtils;
import android.webkit.JavascriptInterface;
import android.webkit.WebView;

import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;
import androidx.core.splashscreen.SplashScreen;

import com.getcapacitor.BridgeActivity;

/**
 * MainActivity — Ngabo
 * ─────────────────────────────────────────────────────────────────────
 * Exposes a static WebView reference so SmsBroadcastReceiver can fire
 * custom DOM events directly into the running JavaScript context.
 * Requests RECEIVE_SMS and READ_SMS at runtime (Android 6+).
 * Registers Android notification channels for business alerts (Android 8+).
 * ─────────────────────────────────────────────────────────────────────
 */
public class MainActivity extends BridgeActivity {

    /** Static reference so SmsBroadcastReceiver can call evaluateJavascript() */
    public static WebView webView = null;

    private static final int SMS_PERMISSION_CODE = 1001;

    // Notification channel IDs — stable identifiers, never change these after launch
    public static final String CHANNEL_BUSINESS_ALERTS = "ngabo_business_alerts";
    public static final String CHANNEL_FRAUD_ALERTS    = "ngabo_fraud_alerts";
    public static final String CHANNEL_FLOAT_WARNINGS  = "ngabo_float_warnings";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        // Install splash screen BEFORE super.onCreate (required by core-splashscreen)
        SplashScreen.installSplashScreen(this);

        super.onCreate(savedInstanceState);

        // Expose the Capacitor WebView to the native SMS bridge
        webView = this.bridge.getWebView();

        // Register notification channels (Android 8.0 Oreo and above)
        registerNotificationChannels();

        // Request SMS permissions at runtime (required Android 6.0+)
        requestSmsPermissions();

        // Add Javascript Interface for Notification Access check
        this.bridge.getWebView().addJavascriptInterface(new Object() {
            @JavascriptInterface
            public boolean isNotificationAccessGranted() {
                String pkgName = getPackageName();
                String flat = Settings.Secure.getString(getContentResolver(), "enabled_notification_listeners");
                if (!TextUtils.isEmpty(flat)) {
                    String[] names = flat.split(":");
                    for (String name : names) {
                        ComponentName cn = ComponentName.unflattenFromString(name);
                        if (cn != null && TextUtils.equals(pkgName, cn.getPackageName())) {
                            return true;
                        }
                    }
                }
                return false;
            }

            @JavascriptInterface
            public void openNotificationSettings() {
                Intent intent = new Intent("android.settings.ACTION_NOTIFICATION_LISTENER_SETTINGS");
                startActivity(intent);
            }
        }, "NgaboNative");
    }

    /**
     * Register all Ngabo notification channels.
     * Channels must be created before posting any notification.
     * Safe to call repeatedly — Android ignores duplicate registrations.
     */
    private void registerNotificationChannels() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return;

        NotificationManager nm = getSystemService(NotificationManager.class);
        if (nm == null) return;

        // Channel 1 — General business alerts (6 PM money-outside reminder, EOD prompts)
        NotificationChannel businessChannel = new NotificationChannel(
            CHANNEL_BUSINESS_ALERTS,
            "Business Alerts",
            NotificationManager.IMPORTANCE_HIGH
        );
        businessChannel.setDescription("Evening float reminders and end-of-day closing prompts");
        businessChannel.enableVibration(true);
        nm.createNotificationChannel(businessChannel);

        // Channel 2 — Fraud alerts (CRITICAL — shown immediately when fraud detected)
        NotificationChannel fraudChannel = new NotificationChannel(
            CHANNEL_FRAUD_ALERTS,
            "Fraud Alerts",
            NotificationManager.IMPORTANCE_MAX
        );
        fraudChannel.setDescription("Immediate alerts when a suspicious or spoofed SMS is detected");
        fraudChannel.enableVibration(true);
        fraudChannel.enableLights(true);
        nm.createNotificationChannel(fraudChannel);

        // Channel 3 — Float warnings (when float drops below safe threshold)
        NotificationChannel floatChannel = new NotificationChannel(
            CHANNEL_FLOAT_WARNINGS,
            "Float Warnings",
            NotificationManager.IMPORTANCE_DEFAULT
        );
        floatChannel.setDescription("Alerts when your MTN or Airtel float drops below UGX 200,000");
        nm.createNotificationChannel(floatChannel);
    }

    /**
     * Request SMS read/receive permissions at runtime.
     * On Android 6+, the user sees a permission dialog on first launch.
     */
    private void requestSmsPermissions() {
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.RECEIVE_SMS)
                != PackageManager.PERMISSION_GRANTED) {
            ActivityCompat.requestPermissions(this,
                new String[]{
                    Manifest.permission.RECEIVE_SMS,
                    Manifest.permission.READ_SMS,
                    Manifest.permission.READ_PHONE_STATE
                },
                SMS_PERMISSION_CODE
            );
        }
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        webView = null; // Prevent memory leaks on activity teardown
    }
}
