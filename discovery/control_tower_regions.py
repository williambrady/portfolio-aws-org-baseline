#!/usr/bin/env python3
"""
Control Tower Regions Helper Script.
Ensures Control Tower governs all available AWS regions.

Usage:
    - In plan mode (DISCOVER_MODE=plan): Shows diff of regions to be added
    - In apply mode (DISCOVER_MODE=apply): Updates Landing Zone with missing regions
"""

import os
import sys
import time

import boto3
from botocore.exceptions import ClientError

# -----------------------------------------------------------------------------
# Control Tower Detection
# -----------------------------------------------------------------------------


def detect_control_tower(primary_region: str) -> dict:
    """Detect if Control Tower Landing Zone is deployed.

    Args:
        primary_region: Primary AWS region to use for API calls

    Returns:
        dict with keys:
            - control_tower_exists: bool
            - landing_zone_arn: str (empty if not found)
            - landing_zone_version: str
            - landing_zone_status: str (ACTIVE, PROCESSING, FAILED)
            - governed_regions: list[str]
            - drift_status: str (IN_SYNC, DRIFTED)
            - latest_available_version: str
    """
    result = {
        "control_tower_exists": False,
        "landing_zone_arn": "",
        "landing_zone_version": "",
        "landing_zone_status": "",
        "governed_regions": [],
        "drift_status": "",
        "latest_available_version": "",
    }

    try:
        ct_client = boto3.client("controltower", region_name=primary_region)

        # List landing zones - returns at most one per organization
        response = ct_client.list_landing_zones()
        landing_zones = response.get("landingZones", [])

        if not landing_zones:
            return result

        # Get the landing zone ARN
        lz_arn = landing_zones[0].get("arn", "")
        if not lz_arn:
            return result

        result["landing_zone_arn"] = lz_arn
        result["control_tower_exists"] = True

        # Get landing zone details
        lz_details = ct_client.get_landing_zone(landingZoneIdentifier=lz_arn)
        landing_zone = lz_details.get("landingZone", {})

        result["landing_zone_version"] = landing_zone.get("version", "")
        result["landing_zone_status"] = landing_zone.get("status", "")
        result["latest_available_version"] = landing_zone.get(
            "latestAvailableVersion", ""
        )
        result["drift_status"] = landing_zone.get("driftStatus", {}).get("status", "")

        # Extract governed regions from manifest
        manifest = landing_zone.get("manifest", {})
        if isinstance(manifest, dict):
            result["governed_regions"] = manifest.get("governedRegions", [])

        return result

    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code == "AccessDeniedException":
            print("    Warning: Access denied to Control Tower APIs")
        elif error_code == "ResourceNotFoundException":
            pass  # No landing zone exists
        else:
            print(f"    Warning: Control Tower API error: {e}")
        return result
    except Exception as e:
        print(f"    Warning: Unexpected error detecting Control Tower: {e}")
        return result


# -----------------------------------------------------------------------------
# Region Discovery
# -----------------------------------------------------------------------------


def get_available_regions() -> list:
    """Get all AWS regions available for this account.

    Returns regions where opt-in-status is 'opt-in-not-required' or 'opted-in'.
    Excludes regions where opt-in-status is 'not-opted-in'.

    Returns:
        list of region names sorted alphabetically
    """
    try:
        ec2_client = boto3.client("ec2", region_name="us-east-1")
        response = ec2_client.describe_regions(AllRegions=True)

        available_regions = []
        for region in response.get("Regions", []):
            region_name = region.get("RegionName", "")
            opt_in_status = region.get("OptInStatus", "")

            # Include regions that are enabled (default or explicitly opted-in)
            if opt_in_status in ("opt-in-not-required", "opted-in"):
                available_regions.append(region_name)

        return sorted(available_regions)

    except ClientError as e:
        print(f"    Warning: Could not describe regions: {e}")
        return []


def get_regions_to_add(governed_regions: list, available_regions: list) -> list:
    """Determine which regions need to be added to Control Tower governance.

    Args:
        governed_regions: List of regions currently governed by Control Tower
        available_regions: List of all available regions for this account

    Returns:
        List of regions that should be added (sorted alphabetically)
    """
    governed_set = set(governed_regions)
    available_set = set(available_regions)

    regions_to_add = available_set - governed_set
    return sorted(list(regions_to_add))


# -----------------------------------------------------------------------------
# Output Formatting
# -----------------------------------------------------------------------------


def print_plan_output(ct_info: dict, regions_to_add: list, available_regions: list):
    """Print Terraform-style plan output showing regions to be added.

    Args:
        ct_info: Control Tower detection result
        regions_to_add: List of regions to add
        available_regions: List of all available regions
    """
    governed = ct_info.get("governed_regions", [])

    if not regions_to_add:
        print("    All available regions are governed")
        print(f"    Governed regions ({len(governed)}): {', '.join(sorted(governed))}")
        return

    print("")
    print("  ~ Control Tower governed regions")
    print("")

    # Show current state
    print(f"    Currently governed ({len(governed)}):")
    for region in sorted(governed):
        print(f"      {region}")

    print("")
    print(f"    Regions to add ({len(regions_to_add)}):")
    for region in regions_to_add:
        print(f"      + {region}")

    print("")
    print(f"    After update ({len(available_regions)}):")
    for region in sorted(available_regions):
        if region in regions_to_add:
            print(f"      + {region}  (new)")
        else:
            print(f"        {region}")


# -----------------------------------------------------------------------------
# Landing Zone Update
# -----------------------------------------------------------------------------


def update_landing_zone_regions(
    ct_info: dict,
    regions_to_add: list,
    primary_region: str,
    wait_for_completion: bool = False,
    max_wait_seconds: int = 1800,  # 30 minutes
) -> dict:
    """Update Landing Zone to govern additional regions.

    Args:
        ct_info: Control Tower detection result
        regions_to_add: List of regions to add
        primary_region: Primary AWS region
        wait_for_completion: Whether to wait for the update to complete
        max_wait_seconds: Maximum time to wait for completion

    Returns:
        dict with keys:
            - success: bool
            - operation_id: str
            - message: str
            - new_regions: list[str]
    """
    result = {
        "success": False,
        "operation_id": "",
        "message": "",
        "new_regions": [],
    }

    if not regions_to_add:
        result["success"] = True
        result["message"] = "No regions to add"
        return result

    lz_arn = ct_info.get("landing_zone_arn", "")
    if not lz_arn:
        result["message"] = "No landing zone ARN available"
        return result

    # Check if landing zone is in a state that allows updates
    lz_status = ct_info.get("landing_zone_status", "")
    if lz_status == "PROCESSING":
        result["message"] = "Landing Zone update already in progress"
        return result
    elif lz_status == "FAILED":
        result["message"] = (
            "Landing Zone is in FAILED state - manual remediation required"
        )
        return result

    try:
        ct_client = boto3.client("controltower", region_name=primary_region)

        # Get current landing zone to retrieve manifest
        lz_details = ct_client.get_landing_zone(landingZoneIdentifier=lz_arn)
        landing_zone = lz_details.get("landingZone", {})
        manifest = landing_zone.get("manifest", {})
        version = landing_zone.get("version", "")

        if not isinstance(manifest, dict):
            result["message"] = "Landing Zone manifest is not in expected format"
            return result

        # Update governed regions in manifest
        current_regions = manifest.get("governedRegions", [])
        new_regions = sorted(list(set(current_regions + regions_to_add)))
        manifest["governedRegions"] = new_regions

        # Call update_landing_zone
        print(f"    Updating Landing Zone to govern {len(new_regions)} regions...")
        response = ct_client.update_landing_zone(
            landingZoneIdentifier=lz_arn, version=version, manifest=manifest
        )

        operation_id = response.get("operationIdentifier", "")
        result["operation_id"] = operation_id
        result["new_regions"] = new_regions

        if wait_for_completion:
            result = wait_for_landing_zone_operation(
                ct_client, operation_id, max_wait_seconds, result
            )
        else:
            result["success"] = True
            result["message"] = (
                f"Landing Zone update initiated (operation: {operation_id})"
            )

        return result

    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code == "ConflictException":
            result["message"] = (
                "Landing Zone update conflict - another operation in progress"
            )
        elif error_code == "AccessDeniedException":
            result["message"] = (
                "Access denied - insufficient permissions for Landing Zone update"
            )
        elif error_code == "ValidationException":
            result["message"] = f"Validation error: {e.response['Error']['Message']}"
        else:
            result["message"] = f"Control Tower API error: {e}"
        return result
    except Exception as e:
        result["message"] = f"Unexpected error updating Landing Zone: {e}"
        return result


def wait_for_landing_zone_operation(
    ct_client, operation_id: str, max_wait_seconds: int, result: dict
) -> dict:
    """Wait for a Landing Zone operation to complete.

    Args:
        ct_client: Control Tower boto3 client
        operation_id: Operation identifier to track
        max_wait_seconds: Maximum time to wait
        result: Result dict to update

    Returns:
        Updated result dict
    """
    start_time = time.time()
    poll_interval = 30  # seconds

    while (time.time() - start_time) < max_wait_seconds:
        try:
            response = ct_client.get_landing_zone_operation(
                operationIdentifier=operation_id
            )
            status = response.get("operationDetails", {}).get("status", "")

            if status == "SUCCEEDED":
                result["success"] = True
                result["message"] = "Landing Zone update completed successfully"
                return result
            elif status == "FAILED":
                status_message = response.get("operationDetails", {}).get(
                    "statusMessage", ""
                )
                result["message"] = f"Landing Zone update failed: {status_message}"
                return result
            elif status == "IN_PROGRESS":
                elapsed = int(time.time() - start_time)
                print(f"    Update in progress... ({elapsed}s elapsed)")
                time.sleep(poll_interval)
            else:
                # Unknown status
                time.sleep(poll_interval)

        except ClientError as e:
            result["message"] = f"Error checking operation status: {e}"
            return result

    result["message"] = (
        f"Timed out waiting for Landing Zone update (operation: {operation_id})"
    )
    return result


# -----------------------------------------------------------------------------
# Main Entry Points
# -----------------------------------------------------------------------------


def run_plan(primary_region: str) -> dict:
    """Run in plan mode - show what would change.

    Args:
        primary_region: Primary AWS region

    Returns:
        dict with control tower info and regions to add
    """
    print("Control Tower Regions:")

    # Detect Control Tower
    ct_info = detect_control_tower(primary_region)

    if not ct_info["control_tower_exists"]:
        print("    (not detected - skipping)")
        return {"control_tower_exists": False}

    print(f"    Landing Zone: {ct_info['landing_zone_arn']}")
    print(f"    Version: {ct_info['landing_zone_version']}")
    print(f"    Status: {ct_info['landing_zone_status']}")
    print(f"    Drift: {ct_info['drift_status']}")

    # Get available regions
    available_regions = get_available_regions()

    # Determine regions to add
    regions_to_add = get_regions_to_add(ct_info["governed_regions"], available_regions)

    # Print plan output
    print_plan_output(ct_info, regions_to_add, available_regions)

    return {
        "control_tower_exists": True,
        "ct_info": ct_info,
        "available_regions": available_regions,
        "regions_to_add": regions_to_add,
    }


def run_apply(primary_region: str, wait: bool = False) -> dict:
    """Run in apply mode - update Landing Zone with missing regions.

    Args:
        primary_region: Primary AWS region
        wait: Whether to wait for update completion

    Returns:
        dict with update result
    """
    print("Control Tower Regions (apply mode):")

    # First run plan to get current state
    plan_result = run_plan(primary_region)

    if not plan_result.get("control_tower_exists"):
        return {"success": True, "message": "Control Tower not detected"}

    regions_to_add = plan_result.get("regions_to_add", [])

    if not regions_to_add:
        print("")
        print(
            "    No regions to add - Landing Zone already governs all available regions"
        )
        return {"success": True, "message": "No regions to add"}

    print("")
    print(f"    Adding {len(regions_to_add)} region(s) to Control Tower governance...")

    # Perform update
    update_result = update_landing_zone_regions(
        plan_result["ct_info"], regions_to_add, primary_region, wait_for_completion=wait
    )

    if update_result["success"]:
        print(f"    {update_result['message']}")
    else:
        print(f"    Warning: {update_result['message']}")

    return update_result


def main():
    """Main entry point for standalone execution."""
    # Get mode from environment (default to plan for safety)
    mode = os.environ.get("DISCOVER_MODE", "plan").lower()

    # Get primary region from environment or default
    primary_region = os.environ.get("PRIMARY_REGION", "us-east-1")

    # Get wait flag from environment
    wait_for_completion = (
        os.environ.get("CT_WAIT_FOR_UPDATE", "false").lower() == "true"
    )

    print("=" * 50)
    print("  Control Tower Regions Helper")
    print("=" * 50)
    print("")
    print(f"Mode: {mode}")
    print(f"Primary Region: {primary_region}")
    print("")

    if mode == "apply":
        run_apply(primary_region, wait=wait_for_completion)
    else:
        run_plan(primary_region)

    print("")
    return 0  # Always return success - this is informational


if __name__ == "__main__":
    sys.exit(main())
