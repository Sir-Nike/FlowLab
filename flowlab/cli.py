import argparse
import json
import threading
import urllib.request
import webbrowser

from .config import DATA, MODELS


def main():
    parser = argparse.ArgumentParser(description="FlowLab network research workbench")
    commands = parser.add_subparsers(dest="command", required=True)
    serve = commands.add_parser("serve", help="Start local dashboard")
    serve.add_argument("--port", type=int, default=8765)
    serve.add_argument("--no-browser", action="store_true")
    setup = commands.add_parser("setup", help="Prepare synthetic packet models and optionally CICIDS2017")
    setup.add_argument("--download", action="store_true")
    setup.add_argument("--per-class", type=int, default=4000)
    prepare = commands.add_parser("prepare-cic")
    prepare.add_argument("--per-class", type=int, default=4000)
    prepare.add_argument("--archive")
    pcaps = commands.add_parser("prepare-pcaps")
    pcaps.add_argument("manifest")
    pcaps.add_argument("--name", default="pcap_training")
    pcaps.add_argument("--prefix", type=int)
    pcaps.add_argument("--context", action="store_true")
    training = commands.add_parser("train")
    training.add_argument("dataset")
    training.add_argument("--hierarchical", action="store_true")
    training.add_argument(
        "--study",
        action="store_true",
        help="Three candidates plus disjoint validation-group temperature calibration",
    )
    training.add_argument("--models", nargs="+", default=None)
    matrix = commands.add_parser("experiment")
    matrix.add_argument("--dataset", default="fixture_completed")
    matrix.add_argument("--scenario", default="DoS", choices=["BENIGN", "DoS", "PortScan", "BruteForce"])
    args = parser.parse_args()
    from . import store

    store.initialize()
    if args.command == "serve":
        import uvicorn

        url = f"http://127.0.0.1:{args.port}"
        try:
            with urllib.request.urlopen(url + "/api/status", timeout=1) as response:
                running = json.load(response)
            if running.get("name") == "FlowLab":
                print(f"FlowLab is already running at {url}")
                if not args.no_browser:
                    webbrowser.open(url)
                return
        except (OSError, ValueError):
            pass

        if not list(MODELS.glob("*.json")):
            print("No trained models. Run ./start.sh --setup or flowlab setup first.")
        if not args.no_browser:
            threading.Timer(1.5, lambda: webbrowser.open(f"http://127.0.0.1:{args.port}")).start()
        uvicorn.run("flowlab.app:app", host="127.0.0.1", port=args.port, access_log=False)
    elif args.command == "setup":
        from .datasets import SOURCE, prepare_cic, prepare_fixture
        from .ml import train

        for prefix in (None, 10):
            meta = prepare_fixture(prefix=prefix)
            train(meta["name"], progress=print)
        archive = DATA / "raw/CICIDS2017_improved.zip"
        if args.download and not archive.exists():
            archive.parent.mkdir(exist_ok=True)
            partial = archive.with_suffix(".part")
            print(f"Downloading corrected CICIDS2017 (328 MiB): {SOURCE}", flush=True)
            urllib.request.urlretrieve(SOURCE, partial)
            partial.rename(archive)
        if archive.exists():
            prepare_cic(archive, args.per_class)
            train("cicids2017", progress=print)
    elif args.command == "prepare-cic":
        from .datasets import prepare_cic

        print(json.dumps(prepare_cic(args.archive, args.per_class), indent=2))
    elif args.command == "prepare-pcaps":
        from .datasets import prepare_pcaps

        print(
            json.dumps(prepare_pcaps(args.manifest, args.name, args.prefix, context=args.context), indent=2)
        )
    elif args.command == "train":
        from .ml import train

        train(args.dataset, args.models, progress=print, study=args.study, hierarchical=args.hierarchical)
    elif args.command == "experiment":
        from .experiments import matrix
        from .ml import MODEL_NAMES

        print(
            matrix(
                {
                    "source": "fixture",
                    "scenario": args.scenario,
                    "seed": 42,
                    "src": "192.168.56.11",
                    "dst": "192.168.56.12",
                    "model_ids": [f"{args.dataset}--{m}" for m in MODEL_NAMES],
                    "rates": [0, 0.01, 0.05, 0.1],
                    "kinds": ["random", "burst"],
                    "seeds": [41, 42, 43],
                },
                progress=print,
            )
        )


if __name__ == "__main__":
    main()
