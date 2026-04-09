"""Model and result persistence using pickle + zip compression.

Saves/loads Python objects as compressed ZIP archives with accompanying
JSON metadata files for human-readable inspection.

File naming convention:
  - train_rslt_<name>.zip     : TrainingResult
  - valid_rslt_<name>.zip     : ValidationResult
  - eval_rslt_<name>.zip      : EvaluationResult
  - <name>_info.json          : Metadata sidecar
"""

import os
import json
import pickle
import zipfile
import logging

logger = logging.getLogger(__name__)


def save_result(obj, name: str, output_dir: str, info: dict = None):
    """Save a result object as a compressed ZIP archive.

    Parameters
    ----------
    obj : any
        Python object to pickle and save.
    name : str
        Base name for the output file (without extension).
    output_dir : str
        Directory to save into.
    info : dict, optional
        Metadata dict to save as JSON sidecar.
    """
    os.makedirs(output_dir, exist_ok=True)

    zip_path = os.path.join(output_dir, f"{name}.zip")
    pkl_name = f"{name}.pkl"

    data = pickle.dumps(obj, protocol=pickle.HIGHEST_PROTOCOL)

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        zf.writestr(pkl_name, data)

    logger.info("Saved result to %s", zip_path)

    if info is not None:
        info_path = os.path.join(output_dir, f"{name}_info.json")
        with open(info_path, "w", encoding="utf-8") as f:
            json.dump(info, f, indent=2, default=_json_default)
        logger.info("Saved info to %s", info_path)


def load_result(path: str):
    """Load a result object from a ZIP archive.

    Parameters
    ----------
    path : str
        Path to the .zip file.

    Returns
    -------
    obj : any
        Unpickled Python object.
    """
    with zipfile.ZipFile(path, "r") as zf:
        names = zf.namelist()
        pkl_name = [n for n in names if n.endswith(".pkl")]
        if not pkl_name:
            raise ValueError(f"No .pkl file found in {path}")
        data = zf.read(pkl_name[0])

    obj = pickle.loads(data)
    logger.info("Loaded result from %s", path)
    return obj


def _json_default(obj):
    """JSON serializer fallback for numpy types."""
    import numpy as np

    if isinstance(obj, (np.integer,)):
        return int(obj)
    if isinstance(obj, (np.floating,)):
        return float(obj)
    if isinstance(obj, np.ndarray):
        return obj.tolist()
    return str(obj)
