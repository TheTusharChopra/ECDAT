"""Mosca-style migration urgency (PART 15).

Michele Mosca's inequality:

        x + y  >  z   =>   you are already late

    x = how long the data must remain confidential  (data lifetime / shelf life)
    y = how long the migration itself will take      (migration time)
    z = how long until a cryptographically relevant quantum computer exists

ECDAT's contribution is to compute this *per asset*, from discovered facts rather
than a single organisational guess: x comes from the application's declared data
retention, y from the effort model, and z from an explicitly configurable horizon.

On z we make no prediction. Nobody can responsibly claim a CRQC arrival year, so z
is a user-controlled scenario parameter with a documented default. The default is
2035 because that is the year NIST IR 8547 targets for the *removal* of quantum-
vulnerable algorithms from its standards -- a policy deadline, which is a defensible
planning anchor precisely because it is not a physics prediction.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from ..models import CryptoAsset, MigrationEffort

# Urgency bands
ALREADY_LATE = "already-late"
CRITICAL = "critical"
URGENT = "urgent"
PLAN_NOW = "plan-now"
MONITOR = "monitor"
NOT_APPLICABLE = "not-applicable"

URGENCY_ORDER = {ALREADY_LATE: 0, CRITICAL: 1, URGENT: 2, PLAN_NOW: 3,
                 MONITOR: 4, NOT_APPLICABLE: 5}

DEFAULT_CRQC_YEAR = 2035
CRQC_HORIZONS = [2030, 2035, 2040, 2045, 2050]

CRQC_RATIONALE = {
    2030: ("Aggressive scenario. Aligns with the most pessimistic expert estimates and "
           "with NSA CNSA 2.0's requirement that national security systems complete "
           "their transition well before 2035."),
    2035: ("ECDAT default. NIST IR 8547 targets the removal of quantum-vulnerable "
           "algorithms from NIST standards by 2035, with high-risk systems transitioning "
           "earlier. This is a policy deadline rather than a physics forecast, which is "
           "what makes it a usable planning anchor."),
    2040: "Moderate scenario reflecting median expert survey responses.",
    2045: "Conservative scenario. Useful for testing whether a finding is urgent under "
          "even optimistic assumptions -- if it still ranks critical here, the case is "
          "unarguable.",
    2050: "Very conservative outer bound.",
}


@dataclass
class Scenario:
    """A Mosca scenario. Every field is operator-controlled."""

    crqc_year: int = DEFAULT_CRQC_YEAR
    # Overrides. None => use the per-asset value discovered/declared.
    data_lifetime_years: int | None = None
    migration_months: int | None = None
    # Safety margin: finish this many years before z rather than exactly at z.
    safety_margin_years: float = 1.0
    label: str = "default"

    def to_dict(self) -> dict:
        return {
            "crqc_year": self.crqc_year,
            "data_lifetime_years": self.data_lifetime_years,
            "migration_months": self.migration_months,
            "safety_margin_years": self.safety_margin_years,
            "label": self.label,
            "crqc_rationale": CRQC_RATIONALE.get(self.crqc_year,
                                                 "Operator-supplied horizon."),
        }


@dataclass
class MoscaResult:
    applicable: bool
    urgency: str
    x_data_lifetime: float
    y_migration_years: float
    z_years_to_crqc: float
    gap: float                      # (x + y + margin) - z ; positive => already late
    deadline_year: float            # latest year migration can start
    years_until_start: float
    explanation: str
    inequality: str
    scenario: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "applicable": self.applicable,
            "urgency": self.urgency,
            "x_data_lifetime_years": round(self.x_data_lifetime, 2),
            "y_migration_years": round(self.y_migration_years, 2),
            "z_years_to_crqc": round(self.z_years_to_crqc, 2),
            "gap_years": round(self.gap, 2),
            "latest_start_year": round(self.deadline_year, 1),
            "years_until_latest_start": round(self.years_until_start, 2),
            "inequality": self.inequality,
            "explanation": self.explanation,
            "scenario": self.scenario,
        }


def _now_year() -> float:
    now = datetime.now()
    return now.year + (now.timetuple().tm_yday - 1) / 365.25


def evaluate(asset: CryptoAsset, scenario: Scenario | None = None) -> MoscaResult:
    sc = scenario or Scenario()
    now = _now_year()
    z = sc.crqc_year - now

    x = float(sc.data_lifetime_years
              if sc.data_lifetime_years is not None
              else (asset.data_lifetime_years if asset.data_lifetime_years is not None else 3))

    months = (sc.migration_months
              if sc.migration_months is not None
              else (asset.migration_months
                    or (asset.migration_effort or MigrationEffort.MODERATE).months))
    y = months / 12.0

    # Mosca's inequality applies to assets whose *confidentiality or authenticity*
    # depends on a Shor-vulnerable primitive. It is not the right instrument for a
    # symmetric cipher or a classically-broken hash, and pretending otherwise would
    # produce authoritative-looking nonsense.
    if not asset.quantum_vulnerable:
        reason = (
            f"Mosca's inequality is not the applicable instrument here. "
            + ("This asset already uses a post-quantum or hybrid mechanism."
               if asset.quantum_class in ("pqc_standardized", "hybrid_pqt")
               else f"{asset.algorithm_label or asset.asset_name} is not vulnerable to "
                    f"Shor's algorithm, so no CRQC arrival date creates a deadline for "
                    f"it. "
                    + ("Its weakness is classical and should be remediated on the "
                       "normal vulnerability timeline, which is more urgent than any "
                       "quantum schedule."
                       if asset.quantum_class == "classically_broken"
                       else "Assess it against symmetric strength policy instead.")))
        return MoscaResult(
            applicable=False, urgency=NOT_APPLICABLE,
            x_data_lifetime=x, y_migration_years=y, z_years_to_crqc=z,
            gap=0.0, deadline_year=float(sc.crqc_year), years_until_start=z,
            explanation=reason,
            inequality=f"x={x:.1f}y + y={y:.1f}y vs z={z:.1f}y (not applicable)",
            scenario=sc.to_dict(),
        )

    gap = (x + y + sc.safety_margin_years) - z
    # Latest year migration can start and still finish before secrecy is breached.
    deadline_year = sc.crqc_year - x - y - sc.safety_margin_years
    years_until_start = deadline_year - now

    if gap > 0:
        if years_until_start < -2:
            urgency = ALREADY_LATE
        else:
            urgency = CRITICAL
    elif years_until_start <= 2:
        urgency = URGENT
    elif years_until_start <= 5:
        urgency = PLAN_NOW
    else:
        urgency = MONITOR

    inequality = (f"x({x:.1f}) + y({y:.1f}) + margin({sc.safety_margin_years:.1f}) "
                  f"= {x + y + sc.safety_margin_years:.1f} "
                  f"{'>' if gap > 0 else '<='} z({z:.1f})")

    if gap > 0:
        expl = (
            f"Mosca condition BREACHED. Data protected by this asset must stay "
            f"confidential for {x:.0f} years, and migrating it is estimated at "
            f"{y * 12:.0f} months. Together with a {sc.safety_margin_years:.0f}-year "
            f"safety margin that is {x + y + sc.safety_margin_years:.1f} years of "
            f"required protection, against only {z:.1f} years before the "
            f"{sc.crqc_year} CRQC horizon. The migration should already have started "
            f"{abs(years_until_start):.1f} years ago. Data captured today is at risk "
            f"even if the migration begins immediately."
        )
    else:
        expl = (
            f"Mosca condition satisfied under the {sc.crqc_year} horizon. "
            f"{x:.0f}-year data lifetime plus {y * 12:.0f}-month migration plus "
            f"{sc.safety_margin_years:.0f}-year margin fits inside the {z:.1f} years "
            f"available. Migration must begin by approximately {deadline_year:.0f} "
            f"({years_until_start:.1f} years from now) to preserve that."
        )

    return MoscaResult(
        applicable=True, urgency=urgency,
        x_data_lifetime=x, y_migration_years=y, z_years_to_crqc=z,
        gap=gap, deadline_year=deadline_year, years_until_start=years_until_start,
        explanation=expl, inequality=inequality, scenario=sc.to_dict(),
    )


def apply(asset: CryptoAsset, scenario: Scenario | None = None) -> MoscaResult:
    res = evaluate(asset, scenario)
    asset.mosca_urgency = res.urgency
    asset.mosca_gap_years = round(res.gap, 2)
    asset.mosca_detail = res.to_dict()
    return res


# ======================================================================================
# Priority = risk x urgency. This is the number that orders the migration queue.
# ======================================================================================
_URGENCY_MULTIPLIER = {
    ALREADY_LATE: 1.30,
    CRITICAL: 1.20,
    URGENT: 1.05,
    PLAN_NOW: 0.90,
    MONITOR: 0.72,
    NOT_APPLICABLE: 1.00,   # classical findings keep their own score, undistorted
}


def priority(asset: CryptoAsset) -> tuple[int, str]:
    """Combine risk score and Mosca urgency into a 0-100 priority and a P-band."""
    mult = _URGENCY_MULTIPLIER.get(asset.mosca_urgency or NOT_APPLICABLE, 1.0)
    score = min(100.0, asset.risk_score * mult)

    if score >= 78:
        band = "P0"
    elif score >= 58:
        band = "P1"
    elif score >= 38:
        band = "P2"
    else:
        band = "P3"

    # A classically broken primitive is always at least P1: it is exploitable today,
    # independently of any quantum consideration. Letting a quantum-driven score bury
    # an active MD5 signature would be an unsafe ordering.
    if asset.quantum_class == "classically_broken" and band in ("P2", "P3"):
        band = "P1"
    return int(round(score)), band
