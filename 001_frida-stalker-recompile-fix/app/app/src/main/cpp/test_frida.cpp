#include <jni.h>
#include <string>
#include <iostream>
#include <sys/mman.h>
#include <android/log.h>
#include <bits/sysconf.h>
#include <cstdio>

typedef uint64_t (*func_t)(uint64_t i);
static inline uint32_t read_ctr_el0();


static uint32_t global_ctr = read_ctr_el0();
static void *exec_addr = nullptr;

void aarch64_sync_cache_range(void *start, size_t len);

extern "C" {

__attribute__((visibility("default")))
jstring mmap_exec(JNIEnv *env, jobject thiz, jbyteArray insnBytes, jint num) {
    size_t page_size = sysconf(_SC_PAGE_SIZE);
    if (page_size == -1) {
        std::cerr << "Failed to get page size!" << std::endl;
        return nullptr;
    }

    void *start_addr = exec_addr;
    int flags = MAP_ANON | MAP_PRIVATE;
    if (start_addr != nullptr) {
        flags |= MAP_FIXED;
    }
    void *mem = mmap(
            start_addr, page_size, PROT_READ | PROT_WRITE | PROT_EXEC,
             flags, -1, 0);
    if (mem == MAP_FAILED) {
        std::cerr << "mmap failed!" << std::endl;
        exec_addr = nullptr;
        return nullptr;
    }
    if (exec_addr == nullptr) {
        exec_addr = mem;
    }
    jsize length = env->GetArrayLength((insnBytes));

    jbyte *code = env->GetByteArrayElements(insnBytes, nullptr);
    std::memcpy(mem, code, length);

    aarch64_sync_cache_range(mem, page_size);

    func_t func = reinterpret_cast<func_t>(mem);

    uint64_t sum = func(num);

    munmap(mem, page_size);

    env->ReleaseByteArrayElements(insnBytes, code, 0);

    char buff[128];
    std::sprintf(buff, "[%p] sum[%lu]", mem, sum);

    return env->NewStringUTF(buff);
}

__attribute__((visibility("default")))
JNIEXPORT jobjectArray JNICALL
Java_com_example_frida_1stalker_1recompile_1fix_MainActivity_mmapExec(
        JNIEnv *env, jobject thiz, jbyteArray inst1, jbyteArray inst2, jint base_num) {
    jclass stringCls = env->FindClass("java/lang/String");
    const jsize test_num = 20;
    jobjectArray resultArray = env->NewObjectArray(test_num, stringCls, nullptr);
    for(jsize i = 0; i < test_num; i++) {
        jbyteArray inst = i % 2 == 0 ? inst1 : inst2;
        jstring result1 = mmap_exec(env, thiz, inst, base_num);
        env->SetObjectArrayElement(resultArray, i, result1);
    }
    return resultArray;
}


}



// 读取 CTR_EL0 寄存器（缓存类型寄存器）
// CTR_EL0 寄存器中：
//   - bits [19:16]：表示数据缓存最小行大小(DminLine)，计算方式为：4 << ((CTR_EL0 >> 16) & 0xF)
//   - bits [3:0]  ：表示指令缓存最小行大小(IminLine)，计算方式为：4 << (CTR_EL0 & 0xF)
static inline uint32_t read_ctr_el0(){
    uint64_t ctr;
    __asm__ volatile(
        "mrs %[ctr], ctr_el0" : [ctr] "=r"(ctr)
    );
    return (uint32_t)ctr;
}


void aarch64_sync_cache_range(void *start, size_t len) {
    uint64_t addr_start = (uint64_t)start;
    uint64_t addr_end = addr_start + len;
    uint32_t ctr = global_ctr;
    // 数据缓存行大小
    int dcache_line_size = 4 << ((ctr >> 16) & 0xF);
    // 指令缓存行大小
    int icache_line_size = 4 << (ctr & 0xF);

    // 清理数据缓存（将数据写回到内存）：
    // 循环遍历整个内存区域，对每个缓存行执行 "dc cvau" 操作
    for(uint64_t addr = addr_start & ~(dcache_line_size - 1)
        ; addr < addr_end
        ; addr += dcache_line_size) {
        __asm__ volatile("DC CVAU, %[addr]": : [addr]"r"(addr) : "memory");
    }
    // 数据同步屏障，确保上面的缓存清理操作完成
    __asm__ volatile("dsb ish": : : "memory");

    // 使指令缓存失效（让 CPU 重新加载新的指令）
    // 遍历整个内存区域，对每个缓存行执行 "ic ivau" 操作
    for(uint64_t addr = addr_start & ~(icache_line_size - 1)
        ; addr < addr_end
        ; addr += icache_line_size) {
        __asm__ volatile("IC IVAU, %[addr]": : [addr]"r"(addr) : "memory");
    }
    // 再次数据同步屏障，确保失效操作完成
    __asm__ volatile("dsb ish": : : "memory");
    // 指令同步屏障，刷新指令流水线
    __asm__ volatile("isb": : : "memory");
}