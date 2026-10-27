from aegis.checks.accounts import CHECKS as ACCOUNT_CHECKS
from aegis.checks.containers import CHECKS as CONTAINER_CHECKS
from aegis.checks.filesystem import CHECKS as FILESYSTEM_CHECKS
from aegis.checks.kernel import CHECKS as KERNEL_CHECKS
from aegis.checks.logging import CHECKS as LOGGING_CHECKS
from aegis.checks.mounts import CHECKS as MOUNT_CHECKS
from aegis.checks.network import CHECKS as NETWORK_CHECKS
from aegis.checks.pam import CHECKS as PAM_CHECKS
from aegis.checks.privilege import CHECKS as PRIVILEGE_CHECKS
from aegis.checks.services import CHECKS as SERVICE_CHECKS
from aegis.checks.ssh import CHECKS as SSH_CHECKS
from aegis.checks.systemd_security import CHECKS as SYSTEMD_CHECKS
from aegis.checks.time_sync import CHECKS as TIME_CHECKS
from aegis.checks.updates import CHECKS as UPDATE_CHECKS

ALL_CHECKS = [
    *SSH_CHECKS,
    *ACCOUNT_CHECKS,
    *PAM_CHECKS,
    *FILESYSTEM_CHECKS,
    *MOUNT_CHECKS,
    *NETWORK_CHECKS,
    *KERNEL_CHECKS,
    *PRIVILEGE_CHECKS,
    *LOGGING_CHECKS,
    *SERVICE_CHECKS,
    *SYSTEMD_CHECKS,
    *TIME_CHECKS,
    *CONTAINER_CHECKS,
    *UPDATE_CHECKS,
]
