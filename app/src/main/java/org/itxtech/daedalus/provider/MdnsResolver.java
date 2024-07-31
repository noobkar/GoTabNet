package org.itxtech.daedalus.provider;

import javax.jmdns.JmDNS;
import javax.jmdns.ServiceInfo;
import java.net.InetAddress;

public class MdnsResolver {

    public static InetAddress resolveMdnsName(String mdnsName) throws Exception {
        JmDNS jmdns = JmDNS.create(InetAddress.getLocalHost());
        ServiceInfo serviceInfo = jmdns.getServiceInfo("_http._tcp.local.", mdnsName);
        if (serviceInfo != null) {
            return serviceInfo.getInetAddresses()[0];
        } else {
            throw new Exception("mDNS name resolution failed for: " + mdnsName);
        }
    }

    public static InetAddress systemResolve(String name) throws Exception {
        return InetAddress.getByName(name);
    }
}
