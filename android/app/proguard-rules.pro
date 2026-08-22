# gomobile bind AAR: the generated smartproxy.mobile.* Java bridge wraps JNI
# calls into the Go engine. R8 must not strip/rename them or StartRouter &
# friends would resolve to missing native symbols at runtime.
-keep class smartproxy.mobile.** { *; }

# Shizuku 探针(M6):AIDL 接口类名是 binder 描述符(客户端按名字匹配 Stub),且
# ShizukuProbeService 由 Shizuku 按类名反射实例化——R8 不能改名/裁剪。
-keep class io.github.yiguihai11.smartproxy.shizuku.IShizukuProbe { *; }
-keep class io.github.yiguihai11.smartproxy.shizuku.ShizukuProbeService { *; }
