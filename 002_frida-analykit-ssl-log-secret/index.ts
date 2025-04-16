import './frida-analykit/script/rpc.js'

import { SSLTools } from './frida-analykit/script/net/ssl.js'
import { help } from './frida-analykit/script/helper.js'


setImmediate(() => {
    SSLTools.attachLogSecret()
    help.$error(`[SSLTools.attachLogSecret] ok`)
})