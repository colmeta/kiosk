package com.kioskcontrol.app;

import android.Manifest;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.webkit.WebView;

import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;

import com.getcapacitor.BridgeActivity;

/**
 * MainActivity — KioskControl UG
 * ─────────────────────────────────────────────────────────────────────
 * Exposes a static WebView reference so SmsBroadcastReceiver can fire
 * custom DOM events directly into the running JavaScript context.
 * Requests RECEIVE_SMS and READ_SMS at runtime (Android 6+).
 * ─────────────────────────────────────────────────────────────────────
 */
public class MainActivity extends BridgeActivity {

    /** Static reference so SmsBroadcastReceiver can call evaluateJavascript() */
    public static WebView webView = null;

    private static final int SMS_PERMISSION_CODE = 1001;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // Expose the Capacitor WebView to the native SMS bridge
        webView = this.bridge.getWebView();

        // Request SMS permissions at runtime (required Android 6.0+)
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
    protected void onDestroy() {
        super.onDestroy();
        webView = null; // Prevent memory leaks
    }
}

