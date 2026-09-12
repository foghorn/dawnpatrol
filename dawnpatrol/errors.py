"""Exception hierarchy. Every failure mode the pipeline distinguishes has a type."""


class DawnPatrolError(Exception):
    """Base for all DawnPatrol errors."""


class ConfigError(DawnPatrolError):
    """Configuration or profile is invalid or incomplete."""


class PluginError(DawnPatrolError):
    """A plugin failed to load or is misdeclared."""


class CollectionError(DawnPatrolError):
    """A source failed to collect. Distinct from 'collected zero records'."""


class VerificationError(DawnPatrolError):
    """Collected data failed a blocking integrity gate."""


class BudgetExceeded(DawnPatrolError):
    """A token, cost, or call ceiling was reached."""


class ProviderError(DawnPatrolError):
    """The model provider failed or returned something unusable."""


class AdjudicationError(DawnPatrolError):
    """The agent's output could not be validated into a Report."""


class DeliveryError(DawnPatrolError):
    """An output plugin failed to deliver."""
