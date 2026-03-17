import shutil
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

TARGET_DIRS = [
    ROOT / "data" / "raw",
    ROOT / "data" / "processed",
    ROOT / "data" / "delta",
    ROOT / "data" / "quarantine",
    ROOT / "data" / "reports",
    ROOT / "data" / "removed",
    ROOT / "data" / "stream_output",
    ROOT / "data" / "stream_output" / "_checkpoint",
    ROOT / "data" / "stream_output" / "delta_stream",
    ROOT / "data" / "stream_output" / "metrics",
    ROOT / "data" / "stream_output" / "reports",
    ROOT / "data" / "stream_output" / "warehouse",
    ROOT / "data" / "diagrams",
    ROOT / "datasets",
    ROOT / "datasets" / "cybersecurity",
    ROOT / "logs",
]

KEEP_ONLY_IN_DATASETS = {"cybersecurity"}

def reset_data_dirs() -> None:
    summary: dict[str, dict[str, int | str]] = {}

    for directory in TARGET_DIRS:
        directory.mkdir(parents=True, exist_ok=True)
        removed_files, removed_dirs = _remove_children(directory)

        (directory / ".gitkeep").touch(exist_ok=True)

        summary[str(directory.relative_to(ROOT))] = {
            "removed_files": removed_files,
            "removed_dirs": removed_dirs,
            "status": "ready",
        }

    print("Data reset summary:")
    for name, stats in summary.items():
        print(
            f"- {name}: files_removed={stats['removed_files']}, "
            f"dirs_removed={stats['removed_dirs']}, status={stats['status']}"
        )


if __name__ == "__main__":
    reset_data_dirs()
