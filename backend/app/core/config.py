"""Typed application settings, loaded once from the environment.

Every configurable value in SentinelAI is declared here. Nothing reads `os.environ`
directly anywhere else in the codebase, which means:

  * a missing or malformed key fails at import time with a clear message, rather
    than as a confusing ``None`` deep inside an HTTP call at hour 20;
  * the full list of secrets the project needs is one file a reviewer can read;
  * swapping SQLite for PostgreSQL is a single env var, not a code change.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration, populated from ``backend/.env`` or the process env."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",  # Tolerate unrelated vars in a shared shell environment.
    )

    # --- AI --------------------------------------------------------------
    # Optional: the regex tier is fully functional without it. An absent key
    # degrades SentinelAI to Tier-1-only rather than breaking startup, which is
    # exactly the behaviour we want if the demo network dies.
    GEMINI_API_KEY: str = ""
    GEMINI_MODEL: str = "gemini-2.5-flash"
    #: Measured, not guessed. gemini-2.5-flash with thinkingBudget=0 on a ~600
    #: token prompt returns in 1.4-1.9s from this machine. The roadmap's original
    #: 1.5s sat exactly in the middle of that spread, which is the worst possible
    #: place for a timeout — half of all healthy calls would have been discarded
    #: as failures. 4s clears the measured p99 with room for venue wifi.
    #:
    #: This does NOT slow the demo down: the Tier-2 gate closes whenever Tier 1
    #: finds something high or critical, so the Aadhaar path never waits on it.
    GEMINI_TIMEOUT_SECONDS: float = 4.0

    # --- Threat intelligence ---------------------------------------------
    SAFE_BROWSING_API_KEY: str = ""
    #: Site checks happen on navigation, not on the typing path, so a slower
    #: budget than Tier 2 is affordable — nobody is waiting mid-sentence.
    SAFE_BROWSING_TIMEOUT_SECONDS: float = 3.0
    #: Total wall-clock ceiling for the whole RDAP lookup, redirect hops
    #: included — see the manual redirect loop in ``services/site/rdap.py`` for
    #: why httpx cannot enforce that itself.
    #:
    #: Measured full-chain, not guessed: sbi.co.in 1.9s, wikipedia.org 2.7s,
    #: uidai.gov.in 3.5s, a .xyz 404 at 4.7s. The original 4.0 sat inside that
    #: spread and was rejecting valid answers. 8s clears the measured worst case
    #: with headroom, and costs nothing in practice because this runs in
    #: parallel with Safe Browsing and only on navigation, never while typing.
    RDAP_TIMEOUT_SECONDS: float = 8.0

    # --- Storage ----------------------------------------------------------
    DATABASE_URL: str = "sqlite:///./sentinel.db"

    # --- HTTP -------------------------------------------------------------
    # CORS is an allowlist, never "*": the backend accepts text the user typed
    # into their bank's website, so any origin being able to call it is a real leak.
    #
    # Held as a raw string, not list[str], on purpose. pydantic-settings treats
    # any complex-typed field in a .env file as JSON and attempts json.loads()
    # *before* field validators run — so a plain CSV value raises SettingsError
    # and no `mode="before"` validator can rescue it. Parsing in a property is
    # the version-stable fix.
    #: Both spellings of the Vite dev server. They are *different origins* to a
    #: browser, and whichever one the user types into the address bar is the one
    #: sent in the Origin header — listing only one turns a working dashboard
    #: into an unexplained CORS failure depending on how it was opened.
    CORS_ALLOW_ORIGINS: str = "http://localhost:5173,http://127.0.0.1:5173"
    RATE_LIMIT_PER_MINUTE: int = 120

    # --- Feature flags ----------------------------------------------------
    ENABLE_GEMINI_TIER: bool = True
    ENABLE_JWT_AUTH: bool = False

    @property
    def cors_origins(self) -> list[str]:
        """CORS allowlist as a list. Accepts ``a,b,c`` or a single origin."""
        return [origin.strip() for origin in self.CORS_ALLOW_ORIGINS.split(",") if origin.strip()]

    @property
    def gemini_tier_available(self) -> bool:
        """True only when Tier-2 is both enabled and actually usable.

        Callers check this instead of testing the flag and the key separately, so
        there is one definition of "can we make an LLM call" in the codebase.
        """
        return self.ENABLE_GEMINI_TIER and bool(self.GEMINI_API_KEY)


@lru_cache
def get_settings() -> Settings:
    """Cached accessor. Used as a FastAPI dependency and by services alike."""
    return Settings()
