

setImmediate(() => {
    Interceptor.attach(
        Module.getExportByName('libdl.so', 'android_dlopen_ext'), {
            onEnter(args) {
                this.filename = args[0].readCString()
                console.error(`[android_dlopen_ext] ${this.filename}`)
            },
            onLeave(retval) {
                const filename: string = this.filename
                if(filename.includes('libtest_frida.so')) {
                    attachMmapExec(Process.findModuleByName(filename)!)
                }
            },
        }
    )

    function attachMmapExec(mod: Module) {
        console.error(`[attachMmapExec] ${JSON.stringify(mod)}`)
        const target = mod.getExportByName("Java_com_example_frida_1stalker_1recompile_1fix_MainActivity_mmapExec")
        Interceptor.attach(target, {
            onEnter(args) {
                console.log(`[mmap_exec] follow => tid[${Process.getCurrentThreadId()}]`)
                Stalker.follow(Process.getCurrentThreadId(), {
                    transform(iterator: StalkerArm64Iterator) {
                        let inst
                        while((inst = iterator.next()) !== null) {
                            // console.log(`[${Process.getCurrentThreadId()}] ${inst}`)
                            iterator.keep()
                        }
                    }
                })
            },
            onLeave(retval) {
                Stalker.unfollow()
                console.error(`[mmap_exec] unfollow => tid[${Process.getCurrentThreadId()}]`)
            },
        })
    }
})