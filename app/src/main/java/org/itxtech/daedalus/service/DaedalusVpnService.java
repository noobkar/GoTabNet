package org.itxtech.daedalus.service;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageManager;
import android.net.ConnectivityManager;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.system.OsConstants;
import android.util.Log;
import androidx.appcompat.app.AlertDialog;
import androidx.core.app.NotificationCompat;
import org.itxtech.daedalus.Daedalus;
import org.itxtech.daedalus.R;
import org.itxtech.daedalus.activity.MainActivity;
import org.itxtech.daedalus.provider.MdnsResolver;
import org.itxtech.daedalus.provider.Provider;
import org.itxtech.daedalus.provider.ProviderPicker;
import org.itxtech.daedalus.provider.TrafficHandler;
import org.itxtech.daedalus.receiver.StatusBarBroadcastReceiver;
import org.itxtech.daedalus.server.AbstractDnsServer;
import org.itxtech.daedalus.server.DnsServer;
import org.itxtech.daedalus.server.DnsServerHelper;
import org.itxtech.daedalus.util.DnsServersDetector;
import org.itxtech.daedalus.util.Logger;
import org.itxtech.daedalus.util.RuleResolver;
import org.minidns.dnsmessage.DnsMessage;
import org.minidns.record.A;
import org.minidns.record.Record;
import android.util.Log;
import javax.jmdns.JmDNS;
import javax.jmdns.ServiceEvent;
import javax.jmdns.ServiceListener;
import java.net.InetAddress;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.io.EOFException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;

public class DaedalusVpnService extends VpnService implements Runnable {
    public static final String ACTION_ACTIVATE = "org.itxtech.daedalus.service.DaedalusVpnService.ACTION_ACTIVATE";
    public static final String ACTION_DEACTIVATE = "org.itxtech.daedalus.service.DaedalusVpnService.ACTION_DEACTIVATE";

    private static final int NOTIFICATION_ACTIVATED = 0;
    private TrafficHandler trafficHandler;

    private static final String TAG = "DaedalusVpnService";
    private static final String CHANNEL_ID = "daedalus_channel_1";
    private static final String CHANNEL_NAME = "daedalus_channel";

    private static final String CLOUDFLARE_DNS = "1.1.1.1";
    private static final String GOOGLE_DNS = "8.8.8.8"; // Google DNS
    private static final String LOCAL_HOST_SUFFIX = ".local"; // Suffix for local network hosts

    public static AbstractDnsServer primaryServer;
    public static AbstractDnsServer secondaryServer;
    private static InetAddress aliasPrimary;
    private static InetAddress aliasSecondary;

    private NotificationCompat.Builder notification = null;
    private boolean running = false;
    private long lastUpdate = 0;
    private boolean statisticQuery;
    private Provider provider;
    private ParcelFileDescriptor descriptor;
    private Thread mThread = null;
    public HashMap<String, AbstractDnsServer> dnsServers;
    private static boolean activated = false;
    private static BroadcastReceiver receiver;
    MDNSSetup mdnsSetup;
    public static boolean isActivated() {
        return activated;
    }

    private static int getPendingIntent(int flag) {
        return Build.VERSION.SDK_INT >= Build.VERSION_CODES.M ? PendingIntent.FLAG_IMMUTABLE | flag : flag;
    }

    @Override
    public void onCreate() {
        super.onCreate();
        if (Daedalus.getPrefs().getBoolean("settings_use_system_dns", false)) {
            registerReceiver(receiver = new BroadcastReceiver() {
                @Override
                public void onReceive(Context context, Intent intent) {
                    updateUpstreamServers(context);
                }
            }, new IntentFilter(ConnectivityManager.CONNECTIVITY_ACTION));
           mdnsSetup=new MDNSSetup();
            mdnsSetup.setupMDNS();
            initTrafficHandler();

        }
    }

    private static void updateUpstreamServers(Context context) {
        String[] servers = DnsServersDetector.getServers(context);
        if (servers != null) {
            if (servers.length >= 2 && (aliasPrimary == null || !aliasPrimary.getHostAddress().equals(servers[0])) &&
                    (aliasSecondary == null || !aliasSecondary.getHostAddress().equals(servers[0])) &&
                    (aliasPrimary == null || !aliasPrimary.getHostAddress().equals(servers[1])) &&
                    (aliasSecondary == null || !aliasSecondary.getHostAddress().equals(servers[1]))) {
                primaryServer.setAddress(servers[0]);
                primaryServer.setPort(DnsServer.DNS_SERVER_DEFAULT_PORT);
                secondaryServer.setAddress(servers[1]);
                secondaryServer.setPort(DnsServer.DNS_SERVER_DEFAULT_PORT);
            } else if ((aliasPrimary == null || !aliasPrimary.getHostAddress().equals(servers[0])) &&
                    (aliasSecondary == null || !aliasSecondary.getHostAddress().equals(servers[0]))) {
                primaryServer.setAddress(servers[0]);
                primaryServer.setPort(DnsServer.DNS_SERVER_DEFAULT_PORT);
                secondaryServer.setAddress(servers[0]);
                secondaryServer.setPort(DnsServer.DNS_SERVER_DEFAULT_PORT);
            } else {
                StringBuilder buf = new StringBuilder();
                for (String server : servers) {
                    buf.append(server).append(" ");
                }
                Logger.error("Invalid upstream DNS " + buf);
            }
            Logger.info("Upstream DNS updated: " + primaryServer.getAddress() + " " + secondaryServer.getAddress());
        } else {
            Logger.error("Cannot obtain upstream DNS server!");
        }
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null) {
            switch (intent.getAction()) {
                case ACTION_ACTIVATE:
                    activated = true;
                    if (Daedalus.getPrefs().getBoolean("settings_notification", true)) {
                        NotificationManager manager = (NotificationManager) this.getSystemService(Context.NOTIFICATION_SERVICE);

                        NotificationCompat.Builder builder;
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                            NotificationChannel channel = new NotificationChannel(CHANNEL_ID, CHANNEL_NAME, NotificationManager.IMPORTANCE_LOW);
                            manager.createNotificationChannel(channel);
                            builder = new NotificationCompat.Builder(this, CHANNEL_ID);
                        } else {
                            builder = new NotificationCompat.Builder(this);
                        }

                        Intent deactivateIntent = new Intent(StatusBarBroadcastReceiver.STATUS_BAR_BTN_DEACTIVATE_CLICK_ACTION);
                        deactivateIntent.setClass(this, StatusBarBroadcastReceiver.class);
                        Intent settingsIntent = new Intent(StatusBarBroadcastReceiver.STATUS_BAR_BTN_SETTINGS_CLICK_ACTION);
                        settingsIntent.setClass(this, StatusBarBroadcastReceiver.class);
                        PendingIntent pIntent = PendingIntent.getActivity(this, 0,
                                new Intent(this, MainActivity.class), getPendingIntent(PendingIntent.FLAG_UPDATE_CURRENT));
                        builder.setWhen(0)
                                .setContentTitle(getResources().getString(R.string.notice_activated))
                                .setDefaults(NotificationCompat.DEFAULT_LIGHTS)
                                .setSmallIcon(R.drawable.ic_security)
                                .setColor(getResources().getColor(R.color.colorPrimary))
                                .setAutoCancel(false)
                                .setOngoing(true)
                                .setTicker(getResources().getString(R.string.notice_activated))
                                .setContentIntent(pIntent)
                                .addAction(R.drawable.ic_clear, getResources().getString(R.string.button_text_deactivate),
                                        PendingIntent.getBroadcast(this, 0,
                                                deactivateIntent, getPendingIntent(PendingIntent.FLAG_UPDATE_CURRENT)))
                                .addAction(R.drawable.ic_settings, getResources().getString(R.string.action_settings),
                                        PendingIntent.getBroadcast(this, 0,
                                                settingsIntent, getPendingIntent(PendingIntent.FLAG_UPDATE_CURRENT)));

                        Notification notification = builder.build();

                        manager.notify(NOTIFICATION_ACTIVATED, notification);

                        this.notification = builder;
                    }

                    Daedalus.initRuleResolver();
                    startThread();
                    Daedalus.updateShortcut(getApplicationContext());
                    if (MainActivity.getInstance() != null) {
                        MainActivity.getInstance().startActivity(new Intent(getApplicationContext(), MainActivity.class)
                                .putExtra(MainActivity.LAUNCH_ACTION, MainActivity.LAUNCH_ACTION_SERVICE_DONE));
                    }
                    return START_STICKY;
                case ACTION_DEACTIVATE:
                    stopThread();
                    return START_NOT_STICKY;
            }
        }
        return START_NOT_STICKY;
    }

    private void startThread() {
        if (this.mThread == null) {
            this.mThread = new Thread(this, "DaedalusVpn");
            this.running = true;
            this.mThread.start();

        }
    }

    @Override
    public void onDestroy() {
        stopThread();
        if (receiver != null) {
            unregisterReceiver(receiver);
            receiver = null;
        }
    }

    private void stopThread() {
        Log.d(TAG, "stopThread");
        activated = false;
        boolean shouldRefresh = false;
        try {
            if (this.descriptor != null) {
                this.descriptor.close();
                this.descriptor = null;
            }
            if (mThread != null) {
                running = false;
                shouldRefresh = true;
                if (provider != null) {
                    provider.shutdown();
                    mThread.interrupt();
                    provider.stop();
                } else {
                    mThread.interrupt();
                }
                mThread = null;
            }
            if (notification != null) {
                NotificationManager notificationManager = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
                notificationManager.cancel(NOTIFICATION_ACTIVATED);
                notification = null;
            }
            // Stop traffic handling
            if (trafficHandler != null) {
                trafficHandler.stopTrafficHandling();
            }
            if (mdnsSetup!=null)
            {
                mdnsSetup.shutdown();
            }
            dnsServers = null;
        } catch (Exception e) {
            Logger.logException(e);
        }
        stopSelf();

        if (shouldRefresh) {
            RuleResolver.clear();
            DnsServerHelper.clearCache();
            Logger.info("Daedalus VPN service has stopped");
        }

        if (shouldRefresh && MainActivity.getInstance() != null) {
            MainActivity.getInstance().startActivity(new Intent(getApplicationContext(), MainActivity.class)
                    .putExtra(MainActivity.LAUNCH_ACTION, MainActivity.LAUNCH_ACTION_SERVICE_DONE));
        } else if (shouldRefresh) {
            Daedalus.updateShortcut(getApplicationContext());
        }
    }

    @Override
    public void onRevoke() {
        stopThread();
    }

    private InetAddress addDnsServer(Builder builder, String format, byte[] ipv6Template, AbstractDnsServer addr)
            throws UnknownHostException {
        int size = dnsServers.size();
        size++;
        if (addr.getAddress().contains("/")) {//https uri
            String alias = String.format(format, size + 1);
            dnsServers.put(alias, addr);
            builder.addRoute(alias, 32);
            return InetAddress.getByName(alias);
        }
        InetAddress address = InetAddress.getByName(addr.getAddress());
        if (address instanceof Inet6Address && ipv6Template == null) {
            Log.i(TAG, "addDnsServer: Ignoring DNS server " + address);
        } else if (address instanceof Inet4Address) {
            String alias = String.format(format, size + 1);
            addr.setHostAddress(address.getHostAddress());
            dnsServers.put(alias, addr);
            builder.addRoute(alias, 32);
            return InetAddress.getByName(alias);
        } else if (address instanceof Inet6Address) {
            ipv6Template[ipv6Template.length - 1] = (byte) (size + 1);
            InetAddress i6addr = Inet6Address.getByAddress(ipv6Template);
            addr.setHostAddress(address.getHostAddress());
            dnsServers.put(i6addr.getHostAddress(), addr);
            return i6addr;
        }
        return null;
    }
    private void initTrafficHandler() {
        if (trafficHandler == null) {
            trafficHandler = new TrafficHandler();
            // If TrafficHandler needs any configuration, do it here
            // For example: trafficHandler.setLocalDomainMap(localDomainMap);
        }
    }
    @Override
    public void run() {
        try {
            DnsServerHelper.buildCache();
            Builder builder = new Builder()
                    .setSession("Daedalus")
                    .setConfigureIntent(PendingIntent.getActivity(this, 0,
                            new Intent(this, MainActivity.class).putExtra(MainActivity.LAUNCH_FRAGMENT, MainActivity.FRAGMENT_SETTINGS),
                            getPendingIntent(PendingIntent.FLAG_ONE_SHOT)));

            if (Daedalus.getPrefs().getBoolean("settings_app_filter_switch", false)) {
                ArrayList<String> apps = Daedalus.configurations.getAppObjects();
                if (apps.size() > 0) {
                    boolean mode = Daedalus.getPrefs().getBoolean("settings_app_filter_mode_switch", false);
                    for (String app : apps) {
                        try {
                            if (mode) {
                                builder.addDisallowedApplication(app);
                            } else {
                                builder.addAllowedApplication(app);
                            }
                            Logger.debug("Added app to list: " + app);
                        } catch (PackageManager.NameNotFoundException e) {
                            Logger.error("Package Not Found:" + app);
                        }
                    }
                }
            }

            String format = null;
            for (String prefix : new String[]{"10.0.0", "192.0.2", "198.51.100", "203.0.113", "192.168.50"}) {
                try {
                    builder.addAddress(prefix + ".1", 32);
                } catch (IllegalArgumentException e) {
                    continue;
                }
                format = prefix + ".%d";
                break;
            }

            boolean advanced = Daedalus.getPrefs().getBoolean("settings_advanced_switch", false);
            statisticQuery = Daedalus.getPrefs().getBoolean("settings_count_query_times", false);
            byte[] ipv6Template = new byte[]{32, 1, 13, (byte) (184 & 0xFF), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
            try {
                InetAddress addr = Inet6Address.getByAddress(ipv6Template);
                Log.d(TAG, "configure: Adding IPv6 address" + addr);
                builder.addAddress(addr, 120);
            } catch (Exception e) {
                Logger.logException(e);
                ipv6Template = null;
            }

            // Use Cloudflare's DNS for all queries
            builder.addDnsServer(CLOUDFLARE_DNS);
            builder.addDnsServer(GOOGLE_DNS); // Add Google DNS as secondary

            if (advanced) {
                builder.setBlocking(true);
                builder.allowFamily(OsConstants.AF_INET);
                builder.allowFamily(OsConstants.AF_INET6);
            }

            descriptor = builder.establish();
            Logger.info("Daedalus VPN service is started");

            provider = ProviderPicker.getProvider(descriptor, this);
            provider.start();
            initTrafficHandler();

            trafficHandler.handleTraffic(descriptor.getFileDescriptor());

            while (running) {
                byte[] packet = provider.readPacket();
                if (packet != null) {
                    handlePacket(packet);
                }
            }
        } catch (Exception e) {
            if (MainActivity.getInstance() != null && !MainActivity.getInstance().isFinishing()) {
                MainActivity.getInstance().runOnUiThread(() -> {
                    if (MainActivity.getInstance() != null && !MainActivity.getInstance().isFinishing()) {
                        new AlertDialog.Builder(MainActivity.getInstance())
                                .setTitle(R.string.error_occurred)
                                .setMessage(Logger.getExceptionMessage(e))
                                .setPositiveButton(android.R.string.ok, (d, id) -> {
                                })
                                .show();
                    }
                });
            }
            Logger.logException(e);
        } finally {
            stopThread();
        }
    }


    public class MDNSSetup {
        private static final String TAG = "MDNSSetup";
        private JmDNS jmdns;
        private ConcurrentHashMap<String, String> localDomainMap = new ConcurrentHashMap<>();
        private ExecutorService executorService = Executors.newSingleThreadExecutor();

        public void setupMDNS() {
            Log.d(TAG, "setupMDNS: Setting up mDNS");
            executorService.execute(() -> {
                try {
                    InetAddress inetAddress = InetAddress.getByName("0.0.0.0");
                    jmdns = JmDNS.create(inetAddress);

                    jmdns.addServiceListener("_http._tcp.local.", new ServiceListener() {
                        @Override
                        public void serviceAdded(ServiceEvent event) {
                            Log.d(TAG, "mDNS service added: " + event.getName());
                            jmdns.requestServiceInfo(event.getType(), event.getName());
                        }

                        @Override
                        public void serviceRemoved(ServiceEvent event) {
                            Log.d(TAG, "mDNS service removed: " + event.getName());
                            localDomainMap.remove(event.getInfo().getName());
                        }

                        @Override
                        public void serviceResolved(ServiceEvent event) {
                            Log.d(TAG, "mDNS service resolved: " + event.getName());
                            String hostAddress = event.getInfo().getInetAddresses()[0].getHostAddress();
                            localDomainMap.put(event.getInfo().getName(), hostAddress);
                        }
                    });
                } catch (Exception e) {
                    Log.e(TAG, "Error setting up mDNS: " + e.getMessage(), e);
                }
            });
        }

        // Remember to call this method when you're done with mDNS
        public void shutdown() {
            if (jmdns != null) {
                try {
                    jmdns.close();
                } catch (Exception e) {
                    Log.e(TAG, "Error closing JmDNS: " + e.getMessage(), e);
                }
            }
            executorService.shutdown();
        }
    }

    private void handlePacket(byte[] packet) {
        try {
            Logger.debug("Received packet: " + Arrays.toString(packet));

            if (packet.length < 28) {
                Logger.debug("Packet too short to be a DNS message. Length: " + packet.length);
                return;
            }

            ByteBuffer buffer = ByteBuffer.wrap(packet).order(ByteOrder.BIG_ENDIAN);
            int version = (buffer.get(0) >> 4) & 0xF;

            if (version != 4 && version != 6) {
                Logger.debug("Not an IPv4 or IPv6 packet. Version: " + version);
                return;
            }

            Logger.debug("IP Version: " + version);

            byte[] dnsPacket;
            if (version == 4) {
                int protocol = buffer.get(9) & 0xFF;
                if (protocol != 17) { // Not UDP
                    Logger.debug("Not a UDP packet. Protocol: " + protocol);
                    return;
                }
                dnsPacket = Arrays.copyOfRange(packet, 28, packet.length);
                Logger.debug("IPv4 UDP packet detected.");
            } else { // IPv6
                int nextHeader = buffer.get(6);
                if (nextHeader == 58) { // ICMPv6
                    Logger.debug("Received an ICMPv6 packet. Skipping.");
                    return;
                }
                if (nextHeader != 17) { // Not UDP
                    Logger.debug("Not a UDP packet. Next header: " + nextHeader);
                    return;
                }
                dnsPacket = Arrays.copyOfRange(packet, 48, packet.length);
                Logger.debug("IPv6 UDP packet detected.");
            }

            processDnsPacket(dnsPacket);
        } catch (Exception e) {
            Logger.logException(e);
        }
    }

    private void processDnsPacket(byte[] dnsPacket) {
        try {
            DnsMessage dnsMessage = new DnsMessage(dnsPacket);
            String queryDomain = dnsMessage.getQuestion().name.toString();

            Logger.debug("Processing DNS packet. Query domain: " + queryDomain);

            if (queryDomain.endsWith("mgocres.com.")) {
                Logger.debug("Handling mgocres.com domain.");
                handleMgocresDomain(dnsMessage);
            } else {
                Logger.debug("Forwarding packet to Cloudflare DNS.");
                provider.forwardPacket(CLOUDFLARE_DNS, DnsServer.DNS_SERVER_DEFAULT_PORT, dnsPacket);
            }
        } catch (Exception e) {
            Logger.logException(e);
        }
    }

    private void handleMgocresDomain(DnsMessage dnsMessage) {
        try {
            String queryDomain = dnsMessage.getQuestion().name.toString();
            String localDomain = queryDomain.replace(".mgocres.com.", ".local");

            InetAddress localServerAddress;
            try {
                org.itxtech.daedalus.server.  Logger.log("Attempting to resolve " + localDomain + " using system resolver.");
                localServerAddress = MdnsResolver.systemResolve(localDomain);
                org.itxtech.daedalus.server.  Logger.log("Resolved " + localDomain + " to IP: " + localServerAddress.getHostAddress() + " using system resolver.");
            } catch (Exception e) {
                org.itxtech.daedalus.server.  Logger.log("System resolver failed. Attempting to resolve " + localDomain + " using mDNS.");
                localServerAddress = MdnsResolver.resolveMdnsName(localDomain);
                org.itxtech.daedalus.server.Logger.log("Resolved " + localDomain + " to IP: " + localServerAddress.getHostAddress() + " using mDNS.");
            }

            DnsMessage.Builder builder = dnsMessage.asBuilder();
            builder.setQrFlag(true);
            builder.addAnswer(new Record<>(dnsMessage.getQuestion().name, Record.TYPE.A, 1, 300,
                    new A(localServerAddress.getAddress())));
            byte[] response = builder.build().toArray();

            org.itxtech.daedalus.server. Logger.log("Sending response for " + queryDomain + " with IP: " + localServerAddress.getHostAddress());

            provider.writePacket(response);
        } catch (Exception e) {
            Logger.logException(e);
        }
    }


    private void handleFacebookDomain(DnsMessage dnsMessage) {
        try {
            String queryDomain = dnsMessage.getQuestion().name.toString();
            String localDomain = queryDomain.replace(".mgcores.com.", LOCAL_HOST_SUFFIX);
            org.itxtech.daedalus.server.Logger.log("LOCAL DOMAIN " + localDomain);

            InetAddress localServerAddress;
            try {
                org.itxtech.daedalus.server.Logger.log("Attempting to resolve " + localDomain + " using system resolver.");
                localServerAddress = MdnsResolver.systemResolve(localDomain);
                org.itxtech.daedalus.server.  Logger.log("Resolved " + localDomain + " to IP: " + localServerAddress.getHostAddress() + " using system resolver.");
            } catch (Exception e) {
                org.itxtech.daedalus.server.   Logger.log("System resolver failed. Attempting to resolve " + localDomain + " using mDNS.");
                localServerAddress = MdnsResolver.resolveMdnsName(localDomain);
                org.itxtech.daedalus.server.  Logger.log("Resolved " + localDomain + " to IP: " + localServerAddress.getHostAddress() + " using mDNS.");
            }

            DnsMessage.Builder builder = dnsMessage.asBuilder();
            builder.setQrFlag(true);
            builder.addAnswer(new Record<>(dnsMessage.getQuestion().name, Record.TYPE.A, 1, 300,
                    new A(localServerAddress.getAddress())));
            byte[] response = builder.build().toArray();

            // Log the response being sent
            org.itxtech.daedalus.server.  Logger.log("Sending response for " + queryDomain + " with IP: " + localServerAddress.getHostAddress());

            provider.writePacket(response);
        } catch (Exception e) {
            Logger.logException(e);
        }
    }

//    private void handlePacket(byte[] packet) {
//        try {
//            // Log packet received
//            org.itxtech.daedalus.server.Logger.log("Received packet: " + Arrays.toString(packet));
//
//            DnsMessage dnsMessage = new DnsMessage(packet);
//            String queryDomain = dnsMessage.getQuestion().name.toString();
//
//            // Log the query domain
//            org.itxtech.daedalus.server.Logger.log("Query domain: " + queryDomain);
//
//            if (queryDomain.endsWith("gtblcl.com.")) {
//                org.itxtech.daedalus.server.Logger.log("Handling gtblcl.com domain.");
//                handleGtblclDomain(dnsMessage);
//            } else {
//                org.itxtech.daedalus.server.Logger.log("Forwarding packet to Cloudflare DNS.");
//                // Forward the DNS query to Cloudflare's DNS
//                provider.forwardPacket(CLOUDFLARE_DNS, DnsServer.DNS_SERVER_DEFAULT_PORT, packet);
//            }
//        } catch (Exception e) {
//            Logger.logException(e);
//        }
//    }
//
//    private void handleGtblclDomain(DnsMessage dnsMessage) {
//        try {
//            String queryDomain = dnsMessage.getQuestion().name.toString();
//            String localDomain = queryDomain.replace(".gtblcl.com.", LOCAL_HOST_SUFFIX);
//
//            InetAddress localServerAddress;
//            try {
//                org.itxtech.daedalus.server.Logger.log("Attempting to resolve " + localDomain + " using system resolver.");
//                localServerAddress = MdnsResolver.systemResolve(localDomain);
//                org.itxtech.daedalus.server.Logger.log("Resolved " + localDomain + " to IP: " + localServerAddress.getHostAddress() + " using system resolver.");
//            } catch (Exception e) {
//                org.itxtech.daedalus.server.Logger.log("System resolver failed. Attempting to resolve " + localDomain + " using mDNS.");
//                localServerAddress = MdnsResolver.resolveMdnsName(localDomain);
//                org.itxtech.daedalus.server.Logger.log("Resolved " + localDomain + " to IP: " + localServerAddress.getHostAddress() + " using mDNS.");
//            }
//
//            DnsMessage.Builder builder = dnsMessage.asBuilder();
//            builder.setQrFlag(true);
//            builder.addAnswer(new Record<>(dnsMessage.getQuestion().name, Record.TYPE.A, 1, 300,
//                    new A(localServerAddress.getAddress())));
//            byte[] response = builder.build().toArray();
//
//            // Log the response being sent
//            org.itxtech.daedalus.server.Logger.log("Sending response for " + queryDomain + " with IP: " + localServerAddress.getHostAddress());
//
//            provider.writePacket(response);
//        } catch (Exception e) {
//            Logger.logException(e);
//        }
//    }


    public void providerLoopCallback() {
        if (statisticQuery) {
            updateUserInterface();
        }
    }

    private void updateUserInterface() {
        long time = System.currentTimeMillis();
        if (time - lastUpdate >= 1000) {
            lastUpdate = time;
            if (notification != null) {
                notification.setContentTitle(getResources().getString(R.string.notice_queries) + " " + provider.getDnsQueryTimes());
                NotificationManager manager = (NotificationManager) this.getSystemService(Context.NOTIFICATION_SERVICE);
                manager.notify(NOTIFICATION_ACTIVATED, notification.build());
            }
        }
    }

    public static class VpnNetworkException extends Exception {
        public VpnNetworkException(String s) {
            super(s);
        }

        public VpnNetworkException(String s, Throwable t) {
            super(s, t);
        }
    }
}
