// Shizuku 探针 AIDL(M6):在 shell UID 进程里做一次隐藏 API 冒烟探测。
// probe() 同步返回多行结果文本,由面板按钮原样回显。
package io.github.yiguihai11.smartproxy.shizuku;

interface IShizukuProbe {
    String probe();
}
