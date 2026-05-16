import "@zsa233/frida-analykit-agent/rpc"
import { SSLTools } from "@zsa233/frida-analykit-agent/ssl"

type TargetKind = "flutter" | "webview"

const attachedModules = new Set<string>()

function moduleKey(mod: Module): string {
    return `${mod.name}@${mod.base}`
}

function basename(path: string): string {
    const zipSuffix = path.lastIndexOf("!")
    const normalized = zipSuffix >= 0 ? path.slice(zipSuffix + 1) : path
    return normalized.split("/").filter(Boolean).pop() ?? normalized
}

function classifyModuleName(name: string): TargetKind | null {
    if (name === "libflutter.so") {
        return "flutter"
    }
    if (
        name === "libmonochrome_64.so" ||
        name === "libmonochrome.so" ||
        name === "libwebviewchromium.so" ||
        name.includes("monochrome") ||
        name.includes("webviewchromium")
    ) {
        return "webview"
    }
    return null
}

function attachBoringsslModule(mod: Module, tag: TargetKind): void {
    const key = moduleKey(mod)
    if (attachedModules.has(key)) {
        return
    }

    try {
        SSLTools.attachBoringsslKeylogFunc({ mod, tag })
        attachedModules.add(key)
        console.error(`[SSLTools.attachBoringsslKeylogFunc] ${tag} ${mod.name} base=${mod.base}`)
    } catch (e) {
        console.error(`[SSLTools.attachBoringsslKeylogFunc] ${tag} ${mod.name} failed: ${e}`)
    }
}

function attachKnownModules(): void {
    for (const mod of Process.enumerateModules()) {
        const tag = classifyModuleName(mod.name)
        if (tag !== null) {
            attachBoringsslModule(mod, tag)
        }
    }
}

function attachAfterDlopen(filename: string | null): void {
    if (filename === null) {
        return
    }

    const name = basename(filename)
    const tag = classifyModuleName(name)
    if (tag === null) {
        return
    }

    const mod = Process.findModuleByName(name)
    if (mod !== null) {
        attachBoringsslModule(mod, tag)
    }
}

function watchDlopen(): void {
    const androidDlopenExt = Module.findExportByName("libdl.so", "android_dlopen_ext")
    if (androidDlopenExt === null) {
        console.error("[watchDlopen] android_dlopen_ext not found")
        return
    }

    Interceptor.attach(androidDlopenExt, {
        onEnter(args) {
            this.filename = args[0].readCString()
        },
        onLeave() {
            attachAfterDlopen(this.filename)
        },
    })
}

setImmediate(() => {
    const libsslAttached = SSLTools.attachLibsslKeylogFunc("libssl")
    console.error(`[SSLTools.attachLibsslKeylogFunc] attached=${libsslAttached}`)

    attachKnownModules()
    watchDlopen()
})
