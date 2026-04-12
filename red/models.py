"""SVM model training with hyperparameter optimization.

Supports GPU acceleration via RAPIDS cuML if available,
falls back to sklearn CPU automatically.

GPU mode (RAPIDS cuML):
    pip install cuml-cu12  # or matching CUDA version

CPU mode (sklearn):
    pip install scikit-learn
"""

import logging
import numpy as np
from sklearn.model_selection import GridSearchCV, StratifiedKFold
from sklearn.metrics import f1_score, matthews_corrcoef, make_scorer
from tqdm import tqdm

logger = logging.getLogger(__name__)

# Auto-detect acceleration backend (priority: NVIDIA GPU > Intel CPU > plain CPU)
GPU_AVAILABLE = False
INTEL_AVAILABLE = False

try:
    from cuml.svm import SVC as cuSVC
    GPU_AVAILABLE = True
    logger.info("RAPIDS cuML detected — using NVIDIA GPU-accelerated SVM")
except ImportError:
    try:
        from sklearnex import patch_sklearn
        patch_sklearn()  # patches sklearn.svm.SVC in-place with Intel oneDAL
        INTEL_AVAILABLE = True
        logger.info("Intel Extension for scikit-learn detected — using Intel CPU acceleration")
    except ImportError:
        logger.info("No acceleration found — using plain sklearn CPU SVM")

from sklearn.svm import SVC, LinearSVC

DEFAULT_PARAM_GRID = {
    "C": np.logspace(-2, 1, num=50),
    "kernel": ["linear"],
    "class_weight": ["balanced", None],
}

SCORERS = {
    "f1": f1_score,
    "mcc": matthews_corrcoef,
}


def train_svc_gridsearch(X, y, param_grid=None, scoring="f1", cv=5, n_jobs=-1):
    """Train SVC using GridSearchCV for hyperparameter optimization.

    Uses GPU (cuML) if available, otherwise falls back to sklearn CPU.
    For GPU mode, GridSearchCV still runs on CPU but individual SVC fits use GPU.

    Parameters
    ----------
    X : array-like
    y : array-like
    param_grid : dict, optional
    scoring : str — "f1" or "mcc"
    cv : int — cross-validation folds
    n_jobs : int — parallel jobs (-1 = all cores)
    """
    if param_grid is None:
        param_grid = DEFAULT_PARAM_GRID

    scorer_fn = SCORERS.get(scoring, f1_score)
    scorer = make_scorer(scorer_fn)

    n_combinations = _count_combinations(param_grid)
    total_fits = n_combinations * cv
    logger.info("GridSearchCV: %d combinations × %d folds = %d fits", n_combinations, cv, total_fits)

    if GPU_AVAILABLE:
        logger.info("GPU mode: grid search on CPU → final fit on GPU")
        best_params, best_score = _cpu_grid_search(X, y, param_grid, scorer, cv, n_jobs)
        estimator = _fit_gpu_svc(X, y, best_params)
        return estimator, best_params, best_score

    # CPU mode with tqdm progress bar
    param_list = list(_iter_param_grid(param_grid))
    best_score = -np.inf
    best_params = None

    with tqdm(total=len(param_list), desc="GridSearch", unit="param", ncols=80) as pbar:
        for params in param_list:
            kf = StratifiedKFold(n_splits=cv)
            scores = []
            for train_idx, val_idx in kf.split(X, y):
                X_tr, X_val = X[train_idx], X[val_idx]
                y_tr, y_val = y[train_idx], y[val_idx]
                svc = SVC(cache_size=2000, **params)
                svc.fit(X_tr, y_tr)
                pred = svc.predict(X_val)
                scores.append(scorer_fn(y_val, pred))
            mean_score = np.mean(scores)
            if mean_score > best_score:
                best_score = mean_score
                best_params = params
            pbar.set_postfix({"best": f"{best_score:.4f}", "C": params.get("C", "?")})
            pbar.update(1)

    logger.info("Best params: %s  Best score: %.4f", best_params, best_score)
    estimator = SVC(cache_size=2000, **best_params)
    estimator.fit(X, y)
    return estimator, best_params, best_score


def _cpu_grid_search(X, y, param_grid, scorer, cv, n_jobs):
    """Run GridSearchCV on CPU to find best params (used in GPU mode)."""
    from sklearn.svm import SVC as skSVC
    from sklearn.metrics import f1_score
    scorer_fn = SCORERS.get("f1", f1_score)
    param_list = list(_iter_param_grid(param_grid))
    best_score = -np.inf
    best_params = None

    with tqdm(total=len(param_list), desc="GridSearch (CPU→GPU)", unit="param", ncols=80) as pbar:
        for params in param_list:
            kf = StratifiedKFold(n_splits=cv)
            scores = []
            for train_idx, val_idx in kf.split(X, y):
                svc = skSVC(cache_size=2000, **params)
                svc.fit(X[train_idx], y[train_idx])
                pred = svc.predict(X[val_idx])
                scores.append(scorer_fn(y[val_idx], pred))
            mean_score = np.mean(scores)
            if mean_score > best_score:
                best_score = mean_score
                best_params = params
            pbar.set_postfix({"best": f"{best_score:.4f}"})
            pbar.update(1)

    logger.info("Best params: %s  Best score: %.4f", best_params, best_score)
    return best_params, best_score


def _fit_gpu_svc(X, y, params):
    """Fit final SVC on GPU using cuML."""
    import cupy as cp
    X_gpu = cp.array(X.toarray() if hasattr(X, 'toarray') else X)
    y_gpu = cp.array(y)
    svc = cuSVC(
        C=params.get("C", 1.0),
        kernel=params.get("kernel", "linear"),
        class_weight=params.get("class_weight", "balanced"),
    )
    logger.info("Fitting final SVC on GPU...")
    svc.fit(X_gpu, y_gpu)
    return svc


def train_svc_fixed(X, y, C=1.0, kernel="linear", class_weight="balanced"):
    """Train SVC with fixed parameters. Uses GPU if available."""
    if GPU_AVAILABLE:
        return _fit_gpu_svc(X, y, {"C": C, "kernel": kernel, "class_weight": class_weight})

    svc = SVC(C=C, kernel=kernel, class_weight=class_weight, cache_size=2000)
    svc.fit(X, y)
    logger.info("Trained SVC with C=%.4f, kernel=%s, class_weight=%s", C, kernel, class_weight)
    return svc


def _count_combinations(param_grid):
    count = 1
    for values in param_grid.values():
        count *= len(values)
    return count


def _iter_param_grid(param_grid):
    """Yield all parameter combinations from a param grid dict."""
    from itertools import product
    keys = list(param_grid.keys())
    for values in product(*param_grid.values()):
        yield dict(zip(keys, values))
