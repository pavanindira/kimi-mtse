"""
k8s_executor.py — Phase 3 Option B: Kubernetes Jobs executor.

Replaces the Docker socket approach used in scan.sh. Instead of calling
`docker run` on the host Docker daemon (which requires socket access = root),
workers call the Kubernetes API to create ephemeral Job resources.

Each scan tool becomes a K8s Job:
  - Isolated namespace (mste-scans)
  - Resource limits enforced by K8s scheduler
  - Automatic cleanup via ttlSecondsAfterFinished
  - No Docker socket required — uses ServiceAccount with Job permissions only

This eliminates the host privilege boundary entirely.

Prerequisites:
    pip install kubernetes
    kubectl apply -f k8s/rbac-scan-jobs.yaml  (grants Jobs permission to the SA)

Usage in tasks.py:
    from k8s_executor import run_tool_job

    exit_code, logs = await run_tool_job(
        scan_id=scan_id,
        tool_name='nuclei',
        image='projectdiscovery/nuclei:latest',
        command=['-target', scan_target, '-je', '/output/findings.json'],
        output_pvc=folder_name,
    )
"""

import logging
import time
from typing import Optional

from kubernetes import client, config
from kubernetes.client.rest import ApiException

logger = logging.getLogger(__name__)

# Load in-cluster config when running inside a Pod;
# fall back to kubeconfig for local development.
try:
    config.load_incluster_config()
    IN_CLUSTER = True
except config.ConfigException:
    config.load_kube_config()
    IN_CLUSTER = False

SCAN_NAMESPACE   = 'mste-scans'
ARTIFACTS_PVC    = 'mste-artifacts'     # same PVC mounted in the API pod
OUTPUT_MOUNT_PATH = '/output'
JOB_TTL_SECONDS  = 3600                 # auto-delete completed jobs after 1h
JOB_TIMEOUT_SECONDS = 1800              # kill jobs running longer than 30 min


def _job_name(scan_id: str, tool: str) -> str:
    """Generate a deterministic, DNS-safe job name."""
    safe_tool = tool.lower().replace('_', '-')[:20]
    return f'mste-{safe_tool}-{scan_id[:12]}'


def run_tool_job(
    scan_id:    str,
    tool_name:  str,
    image:      str,
    command:    list[str],
    env_vars:   dict[str, str] | None = None,
    output_subfolder: str = '',
    timeout:    int = JOB_TIMEOUT_SECONDS,
) -> tuple[int, str]:
    """
    Create a Kubernetes Job for a scan tool and wait for completion.

    Args:
        scan_id:           The MSTE scan ID (used for job naming + log correlation)
        tool_name:         Short name: 'nuclei', 'semgrep', 'trivy', etc.
        image:             Container image to run
        command:           Command + args list
        env_vars:          Optional environment variables to inject
        output_subfolder:  Subfolder under /output to mount for this scan
        timeout:           Max seconds to wait before killing the job

    Returns:
        (exit_code, logs)  exit_code=0 means success
    """
    batch_v1 = client.BatchV1Api()
    name     = _job_name(scan_id, tool_name)

    # Build env list
    env = [
        client.V1EnvVar(name=k, value=v)
        for k, v in (env_vars or {}).items()
    ]

    # Volume mount — same PVC that the API pod uses for scan artifacts
    volume_mount = client.V1VolumeMount(
        name='scan-artifacts',
        mount_path=OUTPUT_MOUNT_PATH,
        sub_path=output_subfolder or '',
    )

    container = client.V1Container(
        name=tool_name,
        image=image,
        command=command,
        env=env,
        volume_mounts=[volume_mount],
        resources=client.V1ResourceRequirements(
            requests={'cpu': '250m', 'memory': '256Mi'},
            limits={'cpu': '2',     'memory': '2Gi'},
        ),
        security_context=client.V1SecurityContext(
            run_as_non_root=True,
            run_as_user=1000,
            allow_privilege_escalation=False,
            read_only_root_filesystem=False,  # tools write temp files
            capabilities=client.V1Capabilities(drop=['ALL']),
        ),
    )

    job = client.V1Job(
        api_version='batch/v1',
        kind='Job',
        metadata=client.V1ObjectMeta(
            name=name,
            namespace=SCAN_NAMESPACE,
            labels={
                'app.kubernetes.io/part-of': 'mste',
                'mste/scan-id':              scan_id,
                'mste/tool':                 tool_name,
            },
        ),
        spec=client.V1JobSpec(
            backoff_limit=0,               # don't retry on failure
            active_deadline_seconds=timeout,
            ttl_seconds_after_finished=JOB_TTL_SECONDS,
            template=client.V1PodTemplateSpec(
                metadata=client.V1ObjectMeta(
                    labels={
                        'mste/scan-id': scan_id,
                        'mste/tool':    tool_name,
                    }
                ),
                spec=client.V1PodSpec(
                    restart_policy='Never',
                    service_account_name='mste-scan-runner',
                    automount_service_account_token=False,
                    containers=[container],
                    volumes=[
                        client.V1Volume(
                            name='scan-artifacts',
                            persistent_volume_claim=client.V1PersistentVolumeClaimVolumeSource(
                                claim_name=ARTIFACTS_PVC
                            ),
                        )
                    ],
                ),
            ),
        ),
    )

    # Create the job
    try:
        batch_v1.create_namespaced_job(namespace=SCAN_NAMESPACE, body=job)
        logger.info(f'Created K8s Job {name} for scan {scan_id}')
    except ApiException as e:
        logger.error(f'Failed to create K8s Job {name}: {e}')
        return 1, str(e)

    # Poll for completion
    start  = time.monotonic()
    while True:
        time.sleep(5)
        try:
            status = batch_v1.read_namespaced_job_status(
                name=name, namespace=SCAN_NAMESPACE
            )
        except ApiException as e:
            logger.warning(f'Error reading job status for {name}: {e}')
            continue

        if status.status.succeeded:
            logs = _get_job_logs(name)
            logger.info(f'Job {name} succeeded')
            return 0, logs

        if status.status.failed:
            logs = _get_job_logs(name)
            logger.warning(f'Job {name} failed')
            return 1, logs

        elapsed = time.monotonic() - start
        if elapsed > timeout:
            logger.warning(f'Job {name} timed out after {timeout}s — deleting')
            _delete_job(name)
            return 1, f'Job timed out after {timeout}s'


def _get_job_logs(job_name: str) -> str:
    """Retrieve logs from the pod created by the job."""
    core_v1 = client.CoreV1Api()
    try:
        pods = core_v1.list_namespaced_pod(
            namespace=SCAN_NAMESPACE,
            label_selector=f'job-name={job_name}',
        )
        if pods.items:
            return core_v1.read_namespaced_pod_log(
                name=pods.items[0].metadata.name,
                namespace=SCAN_NAMESPACE,
            )
    except ApiException as e:
        logger.warning(f'Could not retrieve logs for job {job_name}: {e}')
    return ''


def _delete_job(job_name: str):
    """Force-delete a job and its pods."""
    batch_v1 = client.BatchV1Api()
    try:
        batch_v1.delete_namespaced_job(
            name=job_name,
            namespace=SCAN_NAMESPACE,
            body=client.V1DeleteOptions(propagation_policy='Foreground'),
        )
    except ApiException:
        pass
