# gomobile bind AAR: the generated smartproxy.mobile.* Java bridge wraps JNI
# calls into the Go engine. R8 must not strip/rename them or StartRouter &
# friends would resolve to missing native symbols at runtime.
-keep class smartproxy.mobile.** { *; }
