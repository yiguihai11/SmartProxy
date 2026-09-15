# gomobile bind AAR: the generated smartproxy.mobile.* Java bridge wraps JNI
# calls into the Go engine. R8 must not strip/rename them or StartRouter &
# friends would resolve to missing native symbols at runtime.
-keep class smartproxy.mobile.** { *; }

# Shizuku privileged user service, AIDL interfaces, stubs and models
-keep class io.github.yiguihai11.smartproxy.shizuku.** { *; }
-keep interface io.github.yiguihai11.smartproxy.shizuku.** { *; }
-keep class * extends io.github.yiguihai11.smartproxy.shizuku.IShizukuTetheringService$Stub { *; }
-keep class * extends io.github.yiguihai11.smartproxy.shizuku.ITetheringStatusListener$Stub { *; }
-keep class * extends io.github.yiguihai11.smartproxy.shizuku.ICoreTetheringLease$Stub { *; }
-keep class io.github.yiguihai11.smartproxy.shizuku.TetheringStatusSnapshot { *; }
-keepclassmembers class io.github.yiguihai11.smartproxy.shizuku.TetheringStatusSnapshot {
    public static final android.os.Parcelable$Creator *;
}

