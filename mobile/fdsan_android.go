//go:build android

package mobile

/*
#include <dlfcn.h>
#include <stdint.h>

// Android fdsan error levels:
// 0: ANDROID_FDSAN_ERROR_LEVEL_DISABLED
// 1: ANDROID_FDSAN_ERROR_LEVEL_WARN_ONCE
// 2: ANDROID_FDSAN_ERROR_LEVEL_WARN_ALWAYS
// 3: ANDROID_FDSAN_ERROR_LEVEL_FATAL
static void set_android_fdsan_level(int level) {
    void* handle = dlopen("libc.so", RTLD_NOW);
    if (handle) {
        typedef int (*set_level_fn)(int);
        set_level_fn set_level = (set_level_fn)dlsym(handle, "android_fdsan_set_error_level");
        if (set_level) {
            set_level(level);
        }
        dlclose(handle);
    }
}
*/
import "C"

func init() {
	// Relax fdsan to WARN_ONCE (1) so that file descriptor ownership conflicts
	// (such as Qualcomm qdgralloc/SurfaceFlinger sync fence Binder transactions
	// or concurrent Go/C close races) do not abort the process with SIGABRT.
	C.set_android_fdsan_level(1)
}

// SetFdsanLevel allows tuning or disabling fdsan error handling from Android Java/Kotlin.
// 0=Disabled, 1=WarnOnce (default), 2=WarnAlways, 3=Fatal.
func SetFdsanLevel(level int32) {
	C.set_android_fdsan_level(C.int(level))
}
