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
import android.net.wifi.WifiManager;
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
import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.IpSelector;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.UnknownPacket;

import android.util.Log;
import javax.jmdns.JmDNS;
import javax.jmdns.ServiceEvent;
import javax.jmdns.ServiceInfo;
import javax.jmdns.ServiceListener;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.util.Locale;
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

    private static final String MGOCRES_DOMAIN = "gtblc.com";
    private static final String LOCAL_SUFFIX = ".local";
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
    public static boolean isActivated() {
        return activated;
    }

    private static int getPendingIntent(int flag) {
        return Build.VERSION.SDK_INT >= Build.VERSION_CODES.M ? PendingIntent.FLAG_IMMUTABLE | flag : flag;
    }
    private MDNSResolver mdnsResolver;


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
            try {
                mdnsResolver = new MDNSResolver(this);
                Log.i(TAG, "onCreate: MDNSResolver initialized successfully");
            } catch (Exception e) {
                Log.e(TAG, "onCreate: Failed to initialize MDNSResolver", e);
            }

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
            Log.i(TAG, "run: Starting VPN service");
            Builder builder = new Builder()
                    .setSession("Daedalus")
                    .addAddress("10.1.10.1", 32)
                    .addDnsServer(CLOUDFLARE_DNS)
                    .addDnsServer(GOOGLE_DNS)
                    .allowFamily(OsConstants.AF_INET)
                    .allowFamily(OsConstants.AF_INET6)
                    .addDisallowedApplication(getPackageName());

            // Allow all traffic
            builder.addRoute("0.0.0.0", 0);
            builder.addRoute("::", 0);

            ParcelFileDescriptor descriptor = builder.establish();
            Log.i(TAG, "run: VPN interface established");

            provider = ProviderPicker.getProvider(descriptor, this);
            provider.start();
            Log.i(TAG, "run: Provider started");

            while (running) {
                byte[] packet = provider.readPacket();
                if (packet != null) {
                    Log.d(TAG, "run: Received packet of length " + packet.length);
                    handlePacket(packet);
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "run: Exception in VPN service", e);
            Logger.logException(e);
        } finally {
            Log.i(TAG, "run: Stopping VPN service");
            stopThread();
        }
    }

    private void handlePacket(byte[] packet) {
        try {
            IpPacket ipPacket = (IpPacket) IpSelector.newPacket(packet, 0, packet.length);

            if (ipPacket.getPayload() instanceof UdpPacket) {
                UdpPacket udpPacket = (UdpPacket) ipPacket.getPayload();
                byte[] dnsRawData = udpPacket.getPayload().getRawData();

                DnsMessage dnsMessage = new DnsMessage(dnsRawData);
                String queryDomain = dnsMessage.getQuestion().name.toString();
                Log.d(TAG, "handlePacket: Received DNS query for " + queryDomain);

                // Remove the trailing dot if present
                if (queryDomain.endsWith(".")) {
                    queryDomain = queryDomain.substring(0, queryDomain.length() - 1);
                }

                Log.d(TAG, "handlePacket: Processed query domain: " + queryDomain);
                Log.d(TAG, "handlePacket: MGOCRES_DOMAIN value: " + MGOCRES_DOMAIN);
                Log.d(TAG, "handlePacket: endsWith check: " + queryDomain.endsWith(MGOCRES_DOMAIN));

                if (queryDomain.endsWith(MGOCRES_DOMAIN)) {
                    Log.i(TAG, "handlePacket: Detected mgcores.com domain, handling locally");
                    handleMgocresDomain(dnsMessage, ipPacket);
                } else {
                    Log.i(TAG, "handlePacket: Forwarding query to Cloudflare DNS");
                    provider.forwardPacket(CLOUDFLARE_DNS, DnsServer.DNS_SERVER_DEFAULT_PORT, dnsRawData);
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "handlePacket: Exception while processing packet", e);
            e.printStackTrace();
        }
    }

    private void handleMgocresDomain(DnsMessage dnsMessage, IpPacket originalPacket) {
        try {
            String queryDomain = dnsMessage.getQuestion().name.toString();
            String localDomain = queryDomain.replace("." + MGOCRES_DOMAIN + ".", LOCAL_SUFFIX);
            Log.i(TAG, "handleMgocresDomain: Attempting to resolve " + localDomain);

            if (mdnsResolver == null) {
                Log.i(TAG, "handleMgocresDomain: MDNSResolver is null, initializing");
                mdnsResolver = new MDNSResolver(this);
            }

            InetAddress localServerAddress = mdnsResolver.resolve(localDomain);

            if (localServerAddress != null) {
                Log.i(TAG, "handleMgocresDomain: Resolved " + localDomain + " to " + localServerAddress.getHostAddress());
                // Create DNS response
                DnsMessage.Builder builder = dnsMessage.asBuilder()
                        .setQrFlag(true)
                        .addAnswer(new Record<>(dnsMessage.getQuestion().name, Record.TYPE.A, 1, 300,
                                new A(localServerAddress.getAddress())));
                byte[] response = builder.build().toArray();

                // Create response packet
                UdpPacket originalUdpPacket = (UdpPacket) originalPacket.getPayload();
                if (originalUdpPacket == null || originalPacket.getHeader() == null) {
                    Log.e(TAG, "handleMgocresDomain: Original UDP packet or IP packet header is null");
                    return;
                }

                Log.d(TAG, "handleMgocresDomain: Original UDP packet: " + originalUdpPacket);
                Log.d(TAG, "handleMgocresDomain: Source Port: " + originalUdpPacket.getHeader().getSrcPort());
                Log.d(TAG, "handleMgocresDomain: Destination Port: " + originalUdpPacket.getHeader().getDstPort());

                if (originalPacket instanceof IpV4Packet) {
                    handleIpV4Packet((IpV4Packet) originalPacket, originalUdpPacket, response);
                } else if (originalPacket instanceof IpV6Packet) {
                    handleIpV6Packet((IpV6Packet) originalPacket, originalUdpPacket, response);
                } else {
                    Log.e(TAG, "handleMgocresDomain: Unsupported IP packet type");
                }
            } else {
                Log.w(TAG, "handleMgocresDomain: Failed to resolve " + localDomain + ", forwarding to Cloudflare DNS");
                provider.forwardPacket(CLOUDFLARE_DNS, DnsServer.DNS_SERVER_DEFAULT_PORT, dnsMessage.toArray());
            }
        } catch (Exception e) {
            Log.e(TAG, "handleMgocresDomain: Exception while handling mgcores.com domain", e);
            e.printStackTrace();
            provider.forwardPacket(CLOUDFLARE_DNS, DnsServer.DNS_SERVER_DEFAULT_PORT, dnsMessage.toArray());
        }
    }

    private void handleIpV4Packet(IpV4Packet ipV4Packet, UdpPacket originalUdpPacket, byte[] response) {
        Inet4Address srcAddr = (Inet4Address) ipV4Packet.getHeader().getDstAddr();
        Inet4Address dstAddr = (Inet4Address) ipV4Packet.getHeader().getSrcAddr();
        Log.d(TAG, "handleIpV4Packet: Source IP: " + srcAddr);
        Log.d(TAG, "handleIpV4Packet: Destination IP: " + dstAddr);

        if (srcAddr == null || dstAddr == null) {
            Log.e(TAG, "handleIpV4Packet: Source or destination address is null for IPv4");
            return;
        }

        try {
            UdpPacket.Builder udpBuilder = new UdpPacket.Builder()
                    .srcAddr(srcAddr)
                    .dstAddr(dstAddr)
                    .srcPort(originalUdpPacket.getHeader().getDstPort())
                    .dstPort(originalUdpPacket.getHeader().getSrcPort())
                    .payloadBuilder(new UnknownPacket.Builder().rawData(response))
                    .correctChecksumAtBuild(true)
                    .correctLengthAtBuild(true);

            IpV4Packet.Builder ipV4Builder = new IpV4Packet.Builder(ipV4Packet)
                    .srcAddr(srcAddr)
                    .dstAddr(dstAddr)
                    .payloadBuilder(udpBuilder)
                    .correctChecksumAtBuild(true)
                    .correctLengthAtBuild(true);

            IpV4Packet ipResponse = ipV4Builder.build();
            Log.i(TAG, "handleIpV4Packet: Sending IPv4 response packet");
            provider.writePacket(ipResponse.getRawData());
        } catch (Exception e) {
            Log.e(TAG, "handleIpV4Packet: Error building or sending IPv4 packet", e);
        }
    }

    private void handleIpV6Packet(IpV6Packet ipV6Packet, UdpPacket originalUdpPacket, byte[] response) {
        Inet6Address srcAddr = (Inet6Address) ipV6Packet.getHeader().getDstAddr();
        Inet6Address dstAddr = (Inet6Address) ipV6Packet.getHeader().getSrcAddr();
        Log.d(TAG, "handleIpV6Packet: Source IP: " + srcAddr);
        Log.d(TAG, "handleIpV6Packet: Destination IP: " + dstAddr);

        if (srcAddr == null || dstAddr == null) {
            Log.e(TAG, "handleIpV6Packet: Source or destination address is null for IPv6");
            return;
        }

        try {
            UdpPacket.Builder udpBuilder = new UdpPacket.Builder()
                    .srcAddr(srcAddr)
                    .dstAddr(dstAddr)
                    .srcPort(originalUdpPacket.getHeader().getDstPort())
                    .dstPort(originalUdpPacket.getHeader().getSrcPort())
                    .payloadBuilder(new UnknownPacket.Builder().rawData(response))
                    .correctChecksumAtBuild(true)
                    .correctLengthAtBuild(true);

            IpV6Packet.Builder ipV6Builder = new IpV6Packet.Builder(ipV6Packet)
                    .srcAddr(srcAddr)
                    .dstAddr(dstAddr)
                    .payloadBuilder(udpBuilder)
                    .correctLengthAtBuild(true);

            IpV6Packet ipResponse = ipV6Builder.build();
            Log.i(TAG, "handleIpV6Packet: Sending IPv6 response packet");
            provider.writePacket(ipResponse.getRawData());
        } catch (Exception e) {
            Log.e(TAG, "handleIpV6Packet: Error building or sending IPv6 packet", e);
        }
    }

    private static class MDNSResolver {
        private static final String TAG = "MDNSResolver";
        private final Context context;
        private static final int INITIAL_TIMEOUT = 1000; // 1 second
        private static final int MAX_TIMEOUT = 5000; // 5 seconds
        private static final int MAX_RETRIES = 3;

        MDNSResolver(Context context) {
            Log.i(TAG, "resolve: Aam here");

            this.context = context;
        }

        public InetAddress resolve(String domain) {
            Log.i(TAG, "resolve: Attempting to resolve " + domain);
            try {
                // First, try system DNS resolution
                InetAddress address = InetAddress.getByName(domain);
                Log.i(TAG, "resolve: Resolved " + domain + " to " + address.getHostAddress() + " using system DNS");
                return address;
            } catch (UnknownHostException e) {
                Log.w(TAG, "resolve: System DNS resolution failed for " + domain, e);
            }

            // If system DNS fails, try mDNS query with retries
            int timeout = INITIAL_TIMEOUT;
            for (int retry = 0; retry < MAX_RETRIES; retry++) {
                try {
                    DatagramSocket socket = new DatagramSocket();
                    try {
                        socket.setSoTimeout(timeout);

                        byte[] query = createMDNSQuery(domain);
                        InetAddress multicastGroup = InetAddress.getByName("224.0.0.251");
                        DatagramPacket packet = new DatagramPacket(query, query.length, multicastGroup, 5353);
                        socket.send(packet);

                        byte[] buffer = new byte[1024];
                        DatagramPacket response = new DatagramPacket(buffer, buffer.length);
                        socket.receive(response);

                        InetAddress resolvedAddress = parseResponse(response);
                        if (resolvedAddress != null) {
                            Log.i(TAG, "resolve: Resolved " + domain + " to " + resolvedAddress.getHostAddress() + " using mDNS");
                            return resolvedAddress;
                        }
                    } finally {
                        socket.close();
                    }
                } catch (SocketTimeoutException e) {
                    Log.w(TAG, "resolve: mDNS query timed out for " + domain + " (attempt " + (retry + 1) + "/" + MAX_RETRIES + ")", e);
                    timeout = Math.min(timeout * 2, MAX_TIMEOUT); // Exponential backoff, capped at MAX_TIMEOUT
                } catch (Exception e) {
                    Log.e(TAG, "resolve: mDNS resolution failed for " + domain, e);
                    break; // Exit the retry loop on non-timeout errors
                }
            }

            Log.w(TAG, "resolve: Failed to resolve " + domain + " after " + MAX_RETRIES + " attempts");
            return null;
        }
        private byte[] createMDNSQuery(String domain) {
            // Implement a simple mDNS query packet creation
            // This is a simplified version and may need to be expanded for robustness
            ByteBuffer buffer = ByteBuffer.allocate(512);
            buffer.putShort((short) 0); // Transaction ID
            buffer.putShort((short) 0x0100); // Flags
            buffer.putShort((short) 1); // Questions
            buffer.putShort((short) 0); // Answer RRs
            buffer.putShort((short) 0); // Authority RRs
            buffer.putShort((short) 0); // Additional RRs

            String[] labels = domain.split("\\.");
            for (String label : labels) {
                buffer.put((byte) label.length());
                buffer.put(label.getBytes());
            }
            buffer.put((byte) 0); // End of domain name

            buffer.putShort((short) 1); // Type A
            buffer.putShort((short) 1); // Class IN

            return Arrays.copyOf(buffer.array(), buffer.position());
        }

        private InetAddress parseResponse(DatagramPacket response) {
            // Implement a simple mDNS response parser
            // This is a simplified version and may need to be expanded for robustness
            ByteBuffer buffer = ByteBuffer.wrap(response.getData());
            buffer.position(buffer.position() + 12); // Skip header

            // Skip question section
            while (buffer.get() != 0) {
                // Skip name
            }
            buffer.position(buffer.position() + 4); // Skip type and class

            // Parse answer section
            while (buffer.hasRemaining()) {
                while (buffer.get() != 0) {
                    // Skip name
                }
                short type = buffer.getShort();
                buffer.position(buffer.position() + 6); // Skip class and TTL
                short dataLength = buffer.getShort();

                if (type == 1 && dataLength == 4) { // Type A
                    byte[] addressBytes = new byte[4];
                    buffer.get(addressBytes);
                    try {
                        return InetAddress.getByAddress(addressBytes);
                    } catch (UnknownHostException e) {
                        Log.e(TAG, "parseResponse: Failed to create InetAddress", e);
                    }
                } else {
                    buffer.position(buffer.position() + dataLength);
                }
            }

            return null;
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
