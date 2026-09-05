package io.github.yiguihai11.smartproxy.shizuku;

import android.os.ParcelFileDescriptor;

/** Exposes private core inputs and keeps the protected test network alive. */
interface ICoreTetheringLease {
    ParcelFileDescriptor openEngineConfig();
    boolean isCurrentLaunch(String launchId);
    void holdTestNetwork(in ParcelFileDescriptor tun);
    void releaseTestNetwork();
    String assetFingerprint();
    String[] listAssetFiles();
    ParcelFileDescriptor openAssetFile(String name);
}
