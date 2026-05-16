import "@zsa233/frida-analykit-agent/rpc"
import { SSLTools } from "@zsa233/frida-analykit-agent/ssl"

setImmediate(() => {
    const attached = SSLTools.attachLibsslKeylogFunc("libssl")
    console.error(`[SSLTools.attachLibsslKeylogFunc] attached=${attached}`)
})
