import json
import multiprocessing
import os
from pathlib import Path
import sys

import sb.docker


def analyser(task, result_path):
    probe = sb.docker.execute(task)
    probe.update(
        pid=os.getpid(),
        parent_pid=os.getppid(),
        start_method=multiprocessing.get_start_method(),
        main_module=sys.modules["__main__"].__name__,
        compiler=task.solc_version,
    )
    Path(result_path).write_text(json.dumps({"findings": [], "probe": probe}))


def run(task, result_path):
    # Match the pinned sb.analysis.run boundary: a real spawn Process whose
    # target is imported from sb.analysis, rather than from the bridge script.
    context = multiprocessing.get_context("spawn")
    worker = context.Process(target=analyser, args=(task, result_path))
    worker.start()
    try:
        worker.join(15)
        if worker.is_alive():
            raise RuntimeError("SmartBugs fixture worker timed out")
        if worker.exitcode != 0:
            raise RuntimeError(f"SmartBugs fixture worker exited with {worker.exitcode}")
    finally:
        if worker.is_alive():
            worker.terminate()
            worker.join()
