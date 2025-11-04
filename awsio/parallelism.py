"""Utilities for parallel execution of DataFrame group operations.

This module provides applyParallel which parallelizes pandas groupby.apply-like
work using joblib. It supports plot mode (where an axis may be provided per group),
different backends and optional concatenation of results.
"""
import pandas as pd
from joblib import Parallel, delayed


def applyParallel(
    dfGrouped,
    func,
    n_jobs=-1,
    concat_results=True,
    backend="loky",
    plot_mode=False,
    verbose_par=0,
    *args,
    **kwargs,
):
    """
    Parallelize applying a function over grouped data.

    Args:
        dfGrouped (Iterable): A pandas GroupBy or an iterable of (name, group)
            pairs. If plot_mode=True, dfGrouped is expected to yield ((name, group), ax)
            pairs so that an axis object can be passed to the function.
        func (callable): Function to apply to each group's DataFrame. Must accept
            (group, *args, **kwargs) or (group, ax, *args, **kwargs) in plot_mode.
        n_jobs (int): Number of parallel jobs to use (joblib semantics).
            Default -1 uses all available cores.
        concat_results (bool): If True, the returned results will be concatenated
            into a single DataFrame with outer concatenation via pd.concat.
            If False, a dict mapping group name -> result is returned.
        backend (str): Joblib backend ('loky', 'threading', 'multiprocessing', ...).
        plot_mode (bool): If True, assumes dfGrouped yields axes and forces threading
            backend so matplotlib usage is safe.
        verbose_par (int): Verbosity level passed to joblib.Parallel.
        *args, **kwargs: Additional arguments forwarded to func.

    Returns:
        pd.DataFrame or dict: Concatenated DataFrame when concat_results=True,
        otherwise a dict mapping group name to the result of func(group).

    Notes:
        - The function uses a helper temp_func to return (name, result) pairs that
          are then converted to a dict and optionally concatenated.
    """

    def temp_func(func, name, group, *args, **kwargs):
        return name, func(group, *args, **kwargs)

    if plot_mode:
        backend = "threading"
        series_par = dict(
            Parallel(n_jobs=n_jobs, backend=backend, verbose=verbose_par)(
                delayed(temp_func)(func, name, group, ax=ax, *args, **kwargs)
                for (name, group), ax in dfGrouped
            )
        )

    else:
        series_par = dict(
            Parallel(n_jobs=n_jobs, backend=backend, verbose=verbose_par)(
                delayed(temp_func)(func, name, group, *args, **kwargs)
                for name, group in dfGrouped
            )
        )

    if concat_results:
        return pd.concat(series_par, sort=True)
    else:
        return series_par