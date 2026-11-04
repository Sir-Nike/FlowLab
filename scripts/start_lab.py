"""Start only this project's existing libvirt guests; never creates or alters host networking."""

from pathlib import Path
import shutil
import subprocess
import xml.etree.ElementTree as ET

root = Path(__file__).resolve().parents[1]
if shutil.which("virsh") and (root / "lab/token").exists():
    for i in range(1, 5):
        name = f"lab_flowlab{i}"
        try:
            xml = subprocess.run(
                ["virsh", "-c", "qemu:///system", "dumpxml", name],
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
            if xml.returncode:
                continue
            description = ET.fromstring(xml.stdout).findtext("description", "")
            if str(root / "lab/Vagrantfile") not in description:
                continue
            state = subprocess.run(
                ["virsh", "-c", "qemu:///system", "domstate", name],
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
            if state.stdout.strip() == "shut off":
                subprocess.run(["virsh", "-c", "qemu:///system", "start", name], check=True, timeout=15)
        except (OSError, subprocess.SubprocessError, ET.ParseError) as exc:
            print(f"{name}: {exc}. Use ./lab/init.sh to inspect VM startup.")
