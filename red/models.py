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

logger = logging.getLogger(__name__)

# Auto-detect GPU (RAPIDS cuML)
try:
    from cuml.svm import SVC as cuSVC
    from cuml.svm import LinearSVC as cuLinearSVC
    GPU_AVAILABLE = True
    logger.info("RAPIDS cuML detected — using GPU-accelerated SVM")
except ImportError:
    from sklearn.svm import SVC as cuSVC
    GPU_AVAILABLE = False
    logger.info("RAPIDS cuML not found — using CPU sklearn SVM")

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

    if GPU_AVAILABLE:
        # cuML SVC doesn't support GridSearchCV directly — use CPU grid search
        # but fit final model on GPU
        logger.info("GPU mode: running grid search on CPU, final fit on GPU")
        best_params, best_score = _cpu_grid_search(X, y, param_grid, scorer, cv, n_jobs)
        estimator = _fit_gpu_svc(X, y, best_params)
    else:
        gs = GridSearchCV(
            estimator=SVC(cache_size=2000),
            param_grid=param_grid,
            scoring=scorer,
            cv=StratifiedKFold(n_splits=cv),
            n_jobs=n_jobs,
            refit=True,
        )
        logger.info(
            "Starting GridSearchCV: %d parameter combinations, %d-fold CV",
            _count_combinations(param_grid), cv,
        )
        gs.fit(X, y)
        logger.info("Best params: %s  Best score: %.4f", gs.best_params_, gs.best_score_)
        return gs.best_estimator_, gs.best_params_, gs.best_score_

    return estimator, best_params, best_score


def _cpu_grid_search(X, y, param_grid, scorer, cv, n_jobs):
    """Run GridSearchCV on CPU to find best params, then fit final model on GPU."""
    from sklearn.svm import SVC as skSVC
    gs = GridSearchCV(
        estimator=skSVC(cache_size=2000),
        param_grid=param_grid,
        scoring=scorer,
        cv=StratifiedKFold(n_splits=cv),
        n_jobs=n_jobs,
        refit=False,
    )
    logger.info(
        "GridSearchCV (CPU): %d combinations, %d-fold CV",
        _count_combinations(param_grid), cv,
    )
    gs.fit(X, y)
    logger.info("Best params: %s  Best score: %.4f", gs.best_params_, gs.best_score_)
    return gs.best_params_, gs.best_score_


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
