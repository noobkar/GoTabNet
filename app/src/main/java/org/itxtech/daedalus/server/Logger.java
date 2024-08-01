package org.itxtech.daedalus.server;

import android.util.Log;

public class Logger {
    private static final String TAG = "DaedalusVpnService";

    public static void log(String message) {
        Log.d(TAG, message);
    }

    public static void logException(Exception e) {
        Log.e(TAG, "Exception: " + e.getMessage(), e);
    }
}