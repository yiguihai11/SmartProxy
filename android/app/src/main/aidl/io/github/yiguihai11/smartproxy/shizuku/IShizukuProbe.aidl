// Shizuku 探针 + 持久热点共享 AIDL(M6.1 探针 / M7 热点共享)。
// probe() 一次性冒烟;M7 新增 startHotspot 族:在 shell UID 进程里建 test TUN + 开热点,
// 不 teardown,返回 fd 交给 App 喂给 Go 引擎做双 TUN。停止由 stopHotspot() / App 进程死
// (linkToDeath) 触发。
package io.github.yiguihai11.smartproxy.shizuku;

import android.os.Bundle;
import android.os.IBinder;

interface IShizukuProbe {
    String probe();

    // M7 持久热点共享:建 test TUN + setupTestNetwork 发布 + setPreferTestNetworks(true) +
    // 自动开 WiFi 热点。AIDL 规定 String 只能作 in 参数(不能 out),所以 out 信息(接口名/
    // 错误)塞进 Bundle 返回,key 见 ShizukuProbeService.KEY_PFD / KEY_IFACE / KEY_ERROR:
    //   "pfd"   ParcelFileDescriptor —— test TUN 的 fd。Binder 写 Bundle 时自动 dup,
    //           调用方(App)拿到独立 fd,自己负责 close;服务端持有自己的 tunPfd,由
    //           stopHotspot() / App 死亡回收。成功必含,失败缺省。
    //   "iface" String —— 测试 TUN 接口名(仅成功时)。
    //   "error" String —— 失败原因;成功为空串。
    // appToken:App 传入的 Binder,服务端 linkToDeath —— App 进程死 → 自动 stopHotspot。
    // 已启动时再次调用:直接返回现有 fd(同样自动 dup)。
    Bundle startHotspot(in IBinder appToken);

    // 幂等停止:停热点 → teardown test network → 关 tunPfd → 反注册 → 撤销 prefer。
    void stopHotspot();

    // 热点共享是否正在运行(服务端视角)。
    boolean isHotspotActive();
}
