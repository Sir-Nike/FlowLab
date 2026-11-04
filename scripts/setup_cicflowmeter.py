"""Build the authors' pinned 2022 exporter locally, without host package changes."""

from pathlib import Path
import subprocess
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
COMMIT = "55f60addd21ada7635a79ee3c596a389756552a6"
ARTIFACTS = {
    "commons-lang3": "org/apache/commons/commons-lang3/3.6/commons-lang3-3.6.jar",
    "commons-math3": "org/apache/commons/commons-math3/3.5/commons-math3-3.5.jar",
    "commons-io": "commons-io/commons-io/2.5/commons-io-2.5.jar",
    "slf4j-api": "org/slf4j/slf4j-api/1.7.25/slf4j-api-1.7.25.jar",
    "slf4j-simple": "org/slf4j/slf4j-simple/1.7.25/slf4j-simple-1.7.25.jar",
    "guava": "com/google/guava/guava/23.6-jre/guava-23.6-jre.jar",
    "tika": "org/apache/tika/tika-core/1.17/tika-core-1.17.jar",
    "weka": "nz/ac/waikato/cms/weka/weka-stable/3.6.14/weka-stable-3.6.14.jar",
    "jfreechart": "org/jfree/jfreechart/1.5.0/jfreechart-1.5.0.jar",
}


def main():
    tools = ROOT / "tools"
    tools.mkdir(exist_ok=True)
    source = tools / "CICFlowMeter"
    if not source.exists():
        subprocess.run(
            ["git", "clone", "https://github.com/GintsEngelen/CICFlowMeter.git", str(source)], check=True
        )
    subprocess.run(["git", "-C", str(source), "checkout", COMMIT], check=True)
    jdk = next(tools.glob("jdk8*/bin/javac"), None)
    if not jdk:
        archive = tools / "jdk8.tar.gz"
        urllib.request.urlretrieve(
            "https://api.adoptium.net/v3/binary/latest/8/ga/linux/x64/jdk/hotspot/normal/eclipse", archive
        )
        with tarfile.open(archive) as tar:
            tar.extractall(tools, filter="data")
        jdk = next(tools.glob("jdk8*/bin/javac"))
    runtime = source / "runtime"
    runtime.mkdir(exist_ok=True)
    for name, path in ARTIFACTS.items():
        target = runtime / f"{name}.jar"
        if not target.exists():
            urllib.request.urlretrieve("https://repo.maven.apache.org/maven2/" + path, target)
    # jnetpcap expects the unversioned soname. Keep the alias inside this project.
    alias = runtime / "libpcap.so"
    if not alias.exists():
        candidates = [Path("/lib64/libpcap.so.1"), Path("/usr/lib/x86_64-linux-gnu/libpcap.so.0.8")]
        library = next((p for p in candidates if p.exists()), None)
        if library is None:
            raise RuntimeError("libpcap runtime is required on this Linux host")
        alias.symlink_to(library)
    classes = runtime / "classes"
    classes.mkdir(exist_ok=True)
    cp = f"{runtime}/*:{source}/jnetpcap/linux/jnetpcap-1.4.r1425/jnetpcap.jar"
    sources = [str(p) for p in (source / "src/main/java").rglob("*.java") if p.name != "CICFlowMeter.java"]
    subprocess.run([str(jdk), "-encoding", "UTF-8", "-cp", cp, "-d", str(classes), *sources], check=True)
    (runtime / "build.json").write_text(
        __import__("json").dumps({"commit": COMMIT, "java": str(jdk.with_name("java"))})
    )
    print("Corrected CICFlowMeter ready:", COMMIT)


if __name__ == "__main__":
    main()
