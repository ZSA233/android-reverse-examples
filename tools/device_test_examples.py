#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import shlex
import shutil
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence


REPO_ROOT = Path(__file__).resolve().parents[1]
ADB = shutil.which("adb") or "adb"


@dataclass(frozen=True)
class Example:
    key: str
    name: str
    package: str
    activity: str
    work_dir: Path
    default_apk: Path
    built_apk: Path
    build_command: tuple[str, ...]


EXAMPLES = {
    "001": Example(
        key="001",
        name="frida-stalker-recompile-fix",
        package="com.example.frida_stalker_recompile_fix",
        activity=".MainActivity",
        work_dir=REPO_ROOT / "001_frida-stalker-recompile-fix",
        default_apk=REPO_ROOT / "001_frida-stalker-recompile-fix" / "app-debug.apk",
        built_apk=REPO_ROOT
        / "001_frida-stalker-recompile-fix"
        / "app"
        / "app"
        / "build"
        / "outputs"
        / "apk"
        / "debug"
        / "app-debug.apk",
        build_command=("./gradlew", ":app:assembleDebug"),
    ),
    "002": Example(
        key="002",
        name="frida-analykit-ssl-log-secret",
        package="com.frida_analykit.ssl_log_secret",
        activity=".MainActivity",
        work_dir=REPO_ROOT / "002_frida-analykit-ssl-log-secret",
        default_apk=REPO_ROOT / "002_frida-analykit-ssl-log-secret" / "app-debug.apk",
        built_apk=REPO_ROOT
        / "002_frida-analykit-ssl-log-secret"
        / "app"
        / "app"
        / "build"
        / "outputs"
        / "apk"
        / "debug"
        / "app-debug.apk",
        build_command=("./gradlew", ":app:assembleDebug"),
    ),
    "003": Example(
        key="003",
        name="frida-analykit-static-linked-boringssl",
        package="com.frida_analykit.static_linked_boringssl",
        activity=".MainActivity",
        work_dir=REPO_ROOT / "003_frida-analykit-static-linked-boringssl",
        default_apk=REPO_ROOT
        / "003_frida-analykit-static-linked-boringssl"
        / "samples"
        / "app-release.apk",
        built_apk=REPO_ROOT
        / "003_frida-analykit-static-linked-boringssl"
        / "app"
        / "app"
        / "build"
        / "outputs"
        / "apk"
        / "debug"
        / "app-debug.apk",
        build_command=("./gradlew", ":app:assembleDebug"),
    ),
}


class DeviceTestError(RuntimeError):
    pass


def log(message: str) -> None:
    print(f"[device-test] {message}", flush=True)


def run(
    command: Sequence[str],
    *,
    cwd: Path | None = None,
    check: bool = True,
    timeout: float | None = None,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        list(command),
        cwd=str(cwd) if cwd else None,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
    )
    if check and proc.returncode != 0:
        raise DeviceTestError(
            f"command failed ({proc.returncode}): {' '.join(command)}\n{proc.stdout}"
        )
    return proc


def adb_command(serial: str | None, args: Sequence[str]) -> list[str]:
    command = [ADB]
    if serial:
        command.extend(["-s", serial])
    command.extend(args)
    return command


def adb(serial: str | None, *args: str, check: bool = True, timeout: float | None = None) -> str:
    return run(adb_command(serial, args), check=check, timeout=timeout).stdout


def adb_shell(serial: str, command: str, *, check: bool = True, timeout: float | None = None) -> str:
    return adb(serial, "shell", command, check=check, timeout=timeout)


def connected_devices() -> list[str]:
    output = adb(None, "devices", "-l")
    devices: list[str] = []
    for line in output.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "device":
            devices.append(parts[0])
    return devices


def select_device(serial: str | None) -> str:
    devices = connected_devices()
    if serial:
        if serial not in devices:
            raise DeviceTestError(
                f"requested device {serial!r} is not online; online devices: {devices or 'none'}"
            )
        return serial
    if not devices:
        raise DeviceTestError("no online adb device found; connect a device or pass --serial")
    if len(devices) > 1:
        raise DeviceTestError(
            f"multiple adb devices are online: {', '.join(devices)}; pass --serial"
        )
    return devices[0]


def parse_host_port(frida_host: str) -> int:
    if ":" not in frida_host:
        raise DeviceTestError("--frida-host must be host:port, for example 127.0.0.1:27042")
    try:
        return int(frida_host.rsplit(":", 1)[1])
    except ValueError as exc:
        raise DeviceTestError(f"invalid --frida-host port: {frida_host}") from exc


def frida_server_is_ready(frida_host: str) -> bool:
    frida_ps = shutil.which("frida-ps")
    if not frida_ps:
        return False
    try:
        proc = run([frida_ps, "-H", frida_host], check=False, timeout=8)
    except subprocess.TimeoutExpired:
        return False
    return proc.returncode == 0


def local_frida_version() -> str:
    proc = run(["frida", "--version"], check=False, timeout=5)
    return proc.stdout.strip() or "unknown"


def remote_frida_server_version(serial: str, server_path: str) -> str:
    proc = run(
        adb_command(serial, ["shell", f"su -c {shlex.quote(f'{server_path} --version')}"]),
        check=False,
        timeout=10,
    )
    return proc.stdout.strip() or "unknown"


def ensure_frida_server(serial: str, frida_host: str, server_path: str) -> None:
    port = parse_host_port(frida_host)
    adb(serial, "forward", f"tcp:{port}", f"tcp:{port}")

    log(f"starting frida-server {server_path} on device {serial}")
    server_name = Path(server_path).name
    remote_cmd = (
        f"for name in frida-server {shlex.quote(server_name)}; do "
        "pids=$(pidof $name 2>/dev/null) && kill $pids >/dev/null 2>&1 || true; "
        "done; "
        f"{shlex.quote(server_path)} -l 0.0.0.0:{port} >/dev/null 2>&1 &"
    )
    adb_shell(serial, f"su -c {shlex.quote(remote_cmd)}", check=True, timeout=10)
    deadline = time.time() + 45
    while time.time() < deadline:
        if frida_server_is_ready(frida_host):
            return
        time.sleep(1)
    local_version = local_frida_version()
    remote_version = remote_frida_server_version(serial, server_path)
    raise DeviceTestError(
        f"frida-server did not become reachable at {frida_host}; "
        f"local frida={local_version}, remote server={remote_version}. "
        "Install/start a frida-server with a matching major version."
    )


def build_apk(example: Example) -> Path:
    log(f"building APK for {example.key}")
    run(example.build_command, cwd=example.work_dir / "app", timeout=600)
    if not example.built_apk.exists():
        raise DeviceTestError(f"build completed but APK was not found: {example.built_apk}")
    return example.built_apk


def resolve_apk(example: Example, *, build: bool) -> Path:
    apk = build_apk(example) if build else example.default_apk
    if not apk.exists():
        raise DeviceTestError(f"APK does not exist: {apk}")
    return apk


def install_apk(serial: str, apk: Path, package: str) -> None:
    log(f"installing {apk}")
    proc = run(adb_command(serial, ["install", "-r", "-d", str(apk)]), check=False, timeout=180)
    if proc.returncode == 0:
        return
    if "INSTALL_FAILED_UPDATE_INCOMPATIBLE" not in proc.stdout:
        raise DeviceTestError(
            f"command failed ({proc.returncode}): {ADB} -s {serial} install -r -d {apk}\n{proc.stdout}"
        )
    log(f"uninstalling incompatible existing package {package}")
    adb(serial, "uninstall", package, check=False, timeout=60)
    adb(serial, "install", "-r", "-d", str(apk), timeout=180)


def force_stop(serial: str, package: str) -> None:
    adb_shell(serial, f"am force-stop {package}", check=False)


def clear_app(serial: str, package: str) -> None:
    adb_shell(serial, f"pm clear {package}", check=False)


def wake_device(serial: str) -> None:
    adb_shell(serial, "input keyevent WAKEUP", check=False)
    adb_shell(serial, "wm dismiss-keyguard", check=False)
    adb_shell(serial, "input swipe 500 1900 500 300 300", check=False)
    adb_shell(serial, "svc power stayon true", check=False)
    time.sleep(1)


def app_component(example: Example) -> str:
    return f"{example.package}/{example.activity}"


def ui_contains_package(xml_text: str, package: str) -> bool:
    return any(node.attrib.get("package") == package for node in iter_ui_nodes(xml_text))


def bring_to_front(serial: str, example: Example, *, expected_text: str | None = None) -> None:
    wake_device(serial)
    component = app_component(example)
    deadline = time.time() + 20
    last_xml = ""
    while time.time() < deadline:
        adb_shell(
            serial,
            f"am start -W -n {component} -a android.intent.action.MAIN -c android.intent.category.LAUNCHER >/dev/null",
            check=False,
            timeout=10,
        )
        time.sleep(1)
        last_xml = dump_ui_xml(serial)
        has_package = ui_contains_package(last_xml, example.package)
        has_text = expected_text is None or expected_text in read_ui_text_from_xml(last_xml)
        if has_package and has_text:
            return
    detail = read_ui_text_from_xml(last_xml) if last_xml else ""
    raise DeviceTestError(
        f"failed to bring {example.package} to foreground with {component}; last UI text:\n{detail}"
    )


def dump_ui_xml(serial: str) -> str:
    adb_shell(serial, "uiautomator dump /sdcard/window.xml >/dev/null", check=False, timeout=10)
    return adb(serial, "exec-out", "cat", "/sdcard/window.xml", check=False, timeout=10)


def parse_bounds(bounds: str) -> tuple[int, int, int, int]:
    match = re.fullmatch(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]", bounds)
    if not match:
        raise DeviceTestError(f"invalid bounds: {bounds!r}")
    return tuple(int(v) for v in match.groups())  # type: ignore[return-value]


def node_text(node: ET.Element) -> str:
    return node.attrib.get("text") or node.attrib.get("content-desc") or ""


def iter_ui_nodes(xml_text: str) -> Iterable[ET.Element]:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise DeviceTestError(f"failed to parse uiautomator XML: {exc}\n{xml_text[:500]}") from exc
    yield from root.iter("node")


def read_ui_text_from_xml(xml_text: str) -> str:
    return "\n".join(node_text(node) for node in iter_ui_nodes(xml_text) if node_text(node))


def find_node_by_text(serial: str, text: str, *, timeout: float = 20, exact: bool = False) -> ET.Element:
    deadline = time.time() + timeout
    last_xml = ""
    while time.time() < deadline:
        last_xml = dump_ui_xml(serial)
        for node in iter_ui_nodes(last_xml):
            value = node_text(node)
            matched = value == text if exact else text in value
            if matched:
                return node
        time.sleep(1)
    raise DeviceTestError(f"UI text {text!r} not found; last dump begins:\n{last_xml[:1000]}")


def click_node(serial: str, node: ET.Element, *, dx: int = 0, dy: int = 0) -> None:
    x1, y1, x2, y2 = parse_bounds(node.attrib["bounds"])
    x = (x1 + x2) // 2 + dx
    y = (y1 + y2) // 2 + dy
    adb_shell(serial, f"input tap {x} {y}")


def click_text(serial: str, text: str, *, timeout: float = 20, dx: int = 0, dy: int = 0) -> None:
    node = find_node_by_text(serial, text, timeout=timeout, exact=True)
    click_node(serial, node, dx=dx, dy=dy)


def read_all_ui_text(serial: str) -> str:
    xml_text = dump_ui_xml(serial)
    return read_ui_text_from_xml(xml_text)


def wait_for_ui_pattern(serial: str, pattern: str, *, timeout: float = 30) -> str:
    regex = re.compile(pattern)
    deadline = time.time() + timeout
    last_text = ""
    while time.time() < deadline:
        last_text = read_all_ui_text(serial)
        if regex.search(last_text):
            return last_text
        time.sleep(1)
    raise DeviceTestError(f"UI pattern {pattern!r} not found; last UI text:\n{last_text}")


def wait_for_client_random(paths: Sequence[Path], *, timeout: float = 45) -> Path:
    deadline = time.time() + timeout
    while time.time() < deadline:
        for path in paths:
            if path.exists() and "CLIENT_RANDOM " in path.read_text(errors="ignore"):
                return path
        time.sleep(1)
    listed = "\n".join(str(p) for p in paths)
    raise DeviceTestError(f"CLIENT_RANDOM was not found in expected keylog files:\n{listed}")


def keylog_path(example: Example, tag: str) -> Path:
    return example.work_dir / "data" / "nettools" / tag / "sslkey.log"


def remove_nettools_output(example: Example) -> None:
    shutil.rmtree(example.work_dir / "data" / "nettools", ignore_errors=True)


def npm_build(example: Example) -> None:
    log(f"building agent for {example.key}")
    run(["npm", "run", "build"], cwd=example.work_dir, timeout=120)


def write_device_config(example: Example, serial: str, frida_host: str, server_path: str) -> Path:
    config = example.work_dir / f".device-test-{example.key}.toml"
    config.write_text(
        f"""app = "{example.package}"
jsfile = "_agent.js"

[server]
path = "{server_path}"
host = "{frida_host}"
device = "{serial}"

[agent]
datadir = "./data/"
stdout = "./logs/outerr.log"
stderr = "./logs/outerr.log"

[script.rpc]
batch_max_bytes = 8388608

[script.repl]
globals = ["Process", "Module", "Memory", "Java", "SSLTools"]

[script.nettools]
output_dir = "./data/nettools/"
""",
        encoding="utf-8",
    )
    return config


def start_process(command: Sequence[str], *, cwd: Path, log_name: str) -> subprocess.Popen[str]:
    log_dir = cwd / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / log_name
    stream = log_path.open("w", encoding="utf-8")
    proc = subprocess.Popen(
        list(command),
        cwd=str(cwd),
        text=True,
        stdin=subprocess.PIPE,
        stdout=stream,
        stderr=subprocess.STDOUT,
    )
    proc._device_test_log_stream = stream  # type: ignore[attr-defined]
    proc._device_test_log_path = log_path  # type: ignore[attr-defined]
    return proc


def terminate_process(proc: subprocess.Popen[str] | None) -> None:
    if proc is None:
        return
    if proc.poll() is None:
        if proc.stdin is not None:
            proc.stdin.close()
        proc.terminate()
        try:
            proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
    stream = getattr(proc, "_device_test_log_stream", None)
    if stream is not None:
        stream.close()


def assert_process_running(proc: subprocess.Popen[str], context: str) -> None:
    if proc.poll() is None:
        return
    log_path = getattr(proc, "_device_test_log_path", None)
    log_text = Path(log_path).read_text(errors="ignore") if log_path else ""
    raise DeviceTestError(f"{context} exited early with code {proc.returncode}\n{log_text[-4000:]}")


def prepare_example(serial: str, example: Example, *, build: bool, skip_install: bool) -> None:
    apk = resolve_apk(example, build=build)
    if not skip_install:
        install_apk(serial, apk, example.package)
    clear_app(serial, example.package)
    force_stop(serial, example.package)


def test_001(serial: str, example: Example, args: argparse.Namespace) -> None:
    prepare_example(serial, example, build=args.build_apk, skip_install=args.skip_install)
    npm_build(example)
    proc: subprocess.Popen[str] | None = None
    try:
        proc = start_process(
            [
                "frida",
                "-H",
                args.frida_host,
                "-f",
                example.package,
                "-l",
                "_agent.js",
                "--kill-on-exit",
            ],
            cwd=example.work_dir,
            log_name="device-test-001-frida.log",
        )
        bring_to_front(serial, example, expected_text="开始执行")
        find_node_by_text(serial, "开始执行", timeout=45)
        assert_process_running(proc, "frida 001")
        click_text(serial, "开始执行", timeout=5)
        text = wait_for_ui_pattern(serial, r"sum\[(1|100)\]", timeout=45)
        sums = [int(v) for v in re.findall(r"sum\[(\d+)\]", text)]
        if len(sums) < 20:
            raise DeviceTestError(f"expected at least 20 mmap results, got {len(sums)}:\n{text}")
        expected = [1, 100] * 10
        actual = sums[:20]
        if actual != expected:
            raise DeviceTestError(
                "001 patched Stalker result mismatch; verify --frida-server-path points to "
                f"a compatible patched server.\nactual={actual}\nexpected={expected}"
            )
        log("001 passed")
    finally:
        terminate_process(proc)
        force_stop(serial, example.package)


def start_frida_analykit_spawn(
    serial: str,
    example: Example,
    args: argparse.Namespace,
) -> tuple[subprocess.Popen[str], Path]:
    config = write_device_config(example, serial, args.frida_host, args.frida_server_path)
    command = ["frida-analykit", "spawn", "--config", str(config.name), "--build", "--install"]
    proc = start_process(
        command,
        cwd=example.work_dir,
        log_name=f"device-test-{example.key}-frida-analykit.log",
    )
    return proc, config


def test_002(serial: str, example: Example, args: argparse.Namespace) -> None:
    prepare_example(serial, example, build=args.build_apk, skip_install=args.skip_install)
    remove_nettools_output(example)
    proc: subprocess.Popen[str] | None = None
    config: Path | None = None
    try:
        proc, config = start_frida_analykit_spawn(serial, example, args)
        bring_to_front(serial, example, expected_text="发起请求")
        find_node_by_text(serial, "发起请求", timeout=60)
        assert_process_running(proc, "frida-analykit 002")
        click_text(serial, "发起请求", timeout=5)
        wait_for_ui_pattern(serial, r"(OK|ERROR) - code\[\d+\]", timeout=45)
        path = wait_for_client_random(
            [
                keylog_path(example, "libssl"),
                example.work_dir / "data" / "nettools" / "sslkey.log",
            ],
            timeout=60,
        )
        log(f"002 passed: {path}")
    finally:
        terminate_process(proc)
        if config:
            config.unlink(missing_ok=True)
        force_stop(serial, example.package)


def set_flutter_switch(serial: str, *, enabled: bool) -> None:
    text = read_all_ui_text(serial)
    if enabled and "[Dart]" in text:
        return
    node = find_node_by_text(serial, "Flutter", timeout=10)
    click_node(serial, node, dx=120)
    time.sleep(1)


def test_003(serial: str, example: Example, args: argparse.Namespace) -> None:
    prepare_example(serial, example, build=args.build_apk, skip_install=args.skip_install)
    remove_nettools_output(example)
    proc: subprocess.Popen[str] | None = None
    config: Path | None = None
    try:
        proc, config = start_frida_analykit_spawn(serial, example, args)
        bring_to_front(serial, example, expected_text="发起请求")
        find_node_by_text(serial, "发起请求", timeout=75)
        assert_process_running(proc, "frida-analykit 003")

        click_text(serial, "发起请求", timeout=5)
        wait_for_ui_pattern(serial, r"(OK|ERROR) - code\[\d+\]", timeout=60)
        flutter_log = wait_for_client_random([keylog_path(example, "flutter")], timeout=90)
        log(f"003 flutter passed: {flutter_log}")

        set_flutter_switch(serial, enabled=False)
        click_text(serial, "发起请求", timeout=5)
        wait_for_ui_pattern(serial, r"(OK|ERROR) - code\[\d+\]", timeout=60)
        libssl_log = wait_for_client_random([keylog_path(example, "libssl")], timeout=60)
        log(f"003 libssl passed: {libssl_log}")

        click_text(serial, "WebView打开", timeout=5)
        try:
            webview_log = wait_for_client_random([keylog_path(example, "webview")], timeout=60)
        except DeviceTestError:
            adb_shell(serial, "input keyevent BACK", check=False)
            find_node_by_text(serial, "WebView打开", timeout=20)
            click_text(serial, "WebView打开", timeout=5)
            webview_log = wait_for_client_random([keylog_path(example, "webview")], timeout=90)
        log(f"003 webview passed: {webview_log}")
    finally:
        terminate_process(proc)
        if config:
            config.unlink(missing_ok=True)
        force_stop(serial, example.package)


def parse_examples(value: str) -> list[str]:
    selected = [item.strip() for item in value.split(",") if item.strip()]
    unknown = [item for item in selected if item not in EXAMPLES]
    if unknown:
        raise argparse.ArgumentTypeError(f"unknown example(s): {', '.join(unknown)}")
    return selected


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run android-reverse-examples device checks.")
    parser.add_argument("--serial", help="ADB device serial. Required when multiple devices are online.")
    parser.add_argument(
        "--examples",
        type=parse_examples,
        default=["001", "002", "003"],
        help="Comma-separated example ids to run. Default: 001,002,003.",
    )
    parser.add_argument("--build-apk", action="store_true", help="Build APKs from source before installing.")
    parser.add_argument("--skip-install", action="store_true", help="Do not install APKs before testing.")
    parser.add_argument(
        "--frida-host",
        default="127.0.0.1:27042",
        help="Host used by Frida clients. Default: 127.0.0.1:27042.",
    )
    parser.add_argument(
        "--frida-server-path",
        default="/data/local/tmp/frida-server",
        help="Remote frida-server path. 001 expects this to be a compatible patched server.",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        serial = select_device(args.serial)
        log(f"using adb device {serial}")
        wake_device(serial)
        ensure_frida_server(serial, args.frida_host, args.frida_server_path)
        for key in args.examples:
            example = EXAMPLES[key]
            log(f"running {example.key} {example.name}")
            if key == "001":
                test_001(serial, example, args)
            elif key == "002":
                test_002(serial, example, args)
            elif key == "003":
                test_003(serial, example, args)
        log("all selected examples passed")
        return 0
    except DeviceTestError as exc:
        print(f"[device-test] ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
