package org.itxtech.daedalus.provider;

import android.content.Context;
import android.net.nsd.NsdManager;
import android.net.nsd.NsdServiceInfo;
import android.util.Log;

import java.net.InetAddress;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

public class SystemMDNSResolver {
    private static final String TAG = "SystemMDNSResolver";
    private final NsdManager nsdManager;
    private final Context context;

    public SystemMDNSResolver(Context context) {
        this.context = context;
        this.nsdManager = (NsdManager) context.getSystemService(Context.NSD_SERVICE);
    }

    public InetAddress resolve(String serviceName) {
        final CountDownLatch latch = new CountDownLatch(1);
        final InetAddress[] resolvedAddress = new InetAddress[1];

        NsdServiceInfo serviceInfo = new NsdServiceInfo();
        serviceInfo.setServiceName(serviceName);
        serviceInfo.setServiceType("_http._tcp.");

        nsdManager.resolveService(serviceInfo, new NsdManager.ResolveListener() {
            @Override
            public void onResolveFailed(NsdServiceInfo serviceInfo, int errorCode) {
                Log.e(TAG, "Failed to resolve service: " + errorCode);
                latch.countDown();
            }

            @Override
            public void onServiceResolved(NsdServiceInfo serviceInfo) {
                resolvedAddress[0] = serviceInfo.getHost();
                Log.i(TAG, "Resolved address: " + resolvedAddress[0]);
                latch.countDown();
            }
        });

        try {
            // Wait for up to 5 seconds for resolution
            if (!latch.await(5, TimeUnit.SECONDS)) {
                Log.w(TAG, "Resolution timed out");
            }
        } catch (InterruptedException e) {
            Log.e(TAG, "Resolution interrupted", e);
        }

        return resolvedAddress[0];
    }
}