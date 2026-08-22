// Shizuku 探针 + 持久热点共享 AIDL(M6.1 探针 / M7 热点共享)。
// probe() 一次性冒烟;M7 新增 startHotspot 族:在 shell UID 进程里建 test TUN + 开热点,
// 不 teardown,返回 fd 交给 App 喂给 Go 引擎做双 TUN。停止由 stopHotspot() / App 进程死
// (linkToDeath) 触发。
package io.github.yiguihai11.smartproxy.shizuku;

import android.os.IBinder;
import android.os.ParcelFileDescriptor;

interface IShizukuProbe {
    String probe();

    // M7 持久热点共享:建 test TUN + setupTestNetwork 发布 + setPreferTestNetworks(true) +
    // 自动开 WiFi 热点,全部成功后返回 test TUN 的 ParcelFileDescriptor。
    // Binder 传输 ParcelFileDescriptor 会自动 dup,调用方(App)拿到独立 fd,负责 close;
    // 服务端持有自己的 tunPfd,由 stopHotspot() / App 死亡回收。
    // appToken:App 传入的 Binder,服务端 linkToDeath —— App 进程死 → 自动 stopHotspot。
    // 失败返回 null,error[0] 填原因。已启动时再次调用:直接返回现有 fd(同样自动 dup)。
    ParcelFileDescriptor startHotspot(in IBinder appToken, out String ifaceName, out String error);

    // 幂等停止:停热点 → teardown test network → 关 tunPfd → 反注册 → 撤销 prefer。
    void stopHotspot();

    // 热点共享是否正在运行(服务端视角)。
    boolean isHotspotActive();
}
