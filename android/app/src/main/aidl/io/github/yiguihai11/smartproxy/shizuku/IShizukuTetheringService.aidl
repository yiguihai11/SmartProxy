package io.github.yiguihai11.smartproxy.shizuku;

import io.github.yiguihai11.smartproxy.shizuku.ICoreTetheringLease;
import io.github.yiguihai11.smartproxy.shizuku.ITetheringStatusListener;
import io.github.yiguihai11.smartproxy.shizuku.TetheringStatusSnapshot;

interface IShizukuTetheringService {
    int setWifiHotspotEnabled(boolean enabled) = 2;
    int startRouting(String profileName, in String[] dnsServers, boolean ipv6Enabled, String syncToken, String launchId, ICoreTetheringLease coreLease) = 6;
    int stopRouting() = 7;
    int notifyCoreStopping(String syncToken) = 9;
    int synchronizeRouting(String syncToken, String profileName, in String[] dnsServers, boolean ipv6Enabled, String launchId, ICoreTetheringLease coreLease) = 10;
    int notifyCoreStartFailed(String syncToken, String detail) = 11;
    TetheringStatusSnapshot getStatus(boolean includeIpv6) = 14;
    void setStatusListener(ITetheringStatusListener listener) = 15;
    void destroy() = 16777114;
}
