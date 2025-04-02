#!/usr/bin/expect -f
set timeout 30
set FRIDA_SERVER_BIN /data/local/tmp/frida-server
set SERVER_PORT 6666

exec adb forward tcp:$SERVER_PORT tcp:$SERVER_PORT

spawn adb shell

expect -re {.*:\s*\/\s*[$#]} { 
    send "su\r" 
}
expect -re {.*:\s*\/\s*[$#]} { 
    send "$FRIDA_SERVER_BIN --version\r" 
}
expect -re {.*:\s*\/\s*[$#]} { 
    send "$FRIDA_SERVER_BIN -l 0.0.0.0:$SERVER_PORT\r" 
}
expect {
    -re {.*:\s*\/\s*[$#]} {}
    eof {}
}
