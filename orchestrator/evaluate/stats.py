"""Small, dependency-free statistics used by the scoring and reconciliation code.

Reliability rates are modelled as Beta posteriors (uniform prior): a tool that was right ``c`` times
out of ``n`` has rate ``theta ~ Beta(c + 1, n - c + 1)``.  Comparing two tools is then the probability
``P(theta_A > theta_B)``, which already accounts for how much evidence each side has -- two scans of
evidence yield a probability near 0.5, two hundred yield one near 0 or 1.
"""
from __future__ import annotations

import math
from typing import Optional


def lbeta(a: float, b: float) -> float:
    return math.lgamma(a) + math.lgamma(b) - math.lgamma(a + b)


def _betacf(a: float, b: float, x: float, max_iter: int = 300, eps: float = 3e-14) -> float:
    """Continued fraction for the incomplete beta function (Numerical Recipes, modified Lentz)."""
    tiny = 1e-300
    qab, qap, qam = a + b, a + 1.0, a - 1.0
    c, d = 1.0, 1.0 - qab * x / qap
    if abs(d) < tiny:
        d = tiny
    d = 1.0 / d
    h = d
    for m in range(1, max_iter + 1):
        m2 = 2 * m
        aa = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1.0 + aa * d
        if abs(d) < tiny:
            d = tiny
        c = 1.0 + aa / c
        if abs(c) < tiny:
            c = tiny
        d = 1.0 / d
        h *= d * c
        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        d = 1.0 + aa * d
        if abs(d) < tiny:
            d = tiny
        c = 1.0 + aa / c
        if abs(c) < tiny:
            c = tiny
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < eps:
            break
    return h


def betainc(a: float, b: float, x: float) -> float:
    """Regularised incomplete beta function I_x(a, b)."""
    if x <= 0.0:
        return 0.0
    if x >= 1.0:
        return 1.0
    lbt = -lbeta(a, b) + a * math.log(x) + b * math.log(1.0 - x)
    if x < (a + 1.0) / (a + b + 2.0):
        return math.exp(lbt) * _betacf(a, b, x) / a
    return 1.0 - math.exp(lbt) * _betacf(b, a, 1.0 - x) / b


def beta_cdf(x: float, a: float, b: float) -> float:
    return betainc(a, b, x)


def beta_pdf(x: float, a: float, b: float) -> float:
    if x <= 0.0 or x >= 1.0:
        return 0.0
    return math.exp((a - 1.0) * math.log(x) + (b - 1.0) * math.log(1.0 - x) - lbeta(a, b))


def beta_mean(a: float, b: float) -> float:
    return a / (a + b)


def prob_greater(a1: float, b1: float, a2: float, b2: float, n: int = 600) -> float:
    """P(X > Y) for X ~ Beta(a1, b1), Y ~ Beta(a2, b2) by Simpson integration of pdf_X(x) * cdf_Y(x)."""
    if n % 2:
        n += 1
    h = 1.0 / n
    total = 0.0
    for i in range(n + 1):
        x = i * h
        if i == 0 or i == n:
            w = 1.0
        elif i % 2:
            w = 4.0
        else:
            w = 2.0
        # avoid the (possibly infinite) end points: a1, b1 >= 1 in our use, but be safe
        xx = min(max(x, 1e-9), 1.0 - 1e-9)
        total += w * beta_pdf(xx, a1, b1) * beta_cdf(xx, a2, b2)
    p = total * h / 3.0
    return min(1.0, max(0.0, p))


def prob_above_half(a: float, b: float) -> float:
    return 1.0 - betainc(a, b, 0.5)


def posterior(correct: float, total: float, prior_a: float = 1.0, prior_b: float = 1.0) -> tuple[float, float]:
    """Beta posterior parameters for ``correct`` successes in ``total`` trials (fractional allowed)."""
    correct = max(0.0, min(float(correct), float(total)))
    return prior_a + correct, prior_b + (float(total) - correct)


def wilson_interval(k: float, n: float, z: float = 1.959964) -> tuple[float, float]:
    if n <= 0:
        return 0.0, 1.0
    p = k / n
    denom = 1.0 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return max(0.0, centre - half), min(1.0, centre + half)


def shrink(value: Optional[float], support: float, prior: float, k: float) -> Optional[float]:
    """Shrink a category estimate toward a prior in proportion to its support (``k`` = prior weight)."""
    if value is None:
        return None
    if support <= 0:
        return prior
    return (support * value + k * prior) / (support + k)
