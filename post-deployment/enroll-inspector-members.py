#!/usr/bin/env python3
"""
Enroll existing organization member accounts in Inspector across all regions.

This script should be run from the management account and will assume a role
into the audit account (Inspector delegated administrator) to associate all
existing member accounts with Inspector in every AWS region.

New accounts joining the organization will be automatically enrolled via
aws_inspector2_organization_configuration auto_enable settings.

Usage:
    # Dry run (show what would be enrolled)
    python3 enroll-inspector-members.py --audit-account-id 123456789012

    # Actually enroll accounts
    python3 enroll-inspector-members.py --audit-account-id 123456789012 --apply
"""

import argparse
import sys

import boto3
from botocore.exceptions import ClientError


def get_all_regions():
    """Get all enabled AWS regions."""
    ec2_client = boto3.client("ec2")
    regions = ec2_client.describe_regions(AllRegions=False)["Regions"]
    return sorted([r["RegionName"] for r in regions])


def assume_audit_role(
    audit_account_id: str, role_name: str = "OrganizationAccountAccessRole"
):
    """Assume role into the audit account and return a session."""
    sts = boto3.client("sts")
    role_arn = f"arn:aws:iam::{audit_account_id}:role/{role_name}"

    try:
        response = sts.assume_role(
            RoleArn=role_arn, RoleSessionName="InspectorEnrollment"
        )
        credentials = response["Credentials"]
        return boto3.Session(
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"],
        )
    except ClientError as e:
        print(f"Error assuming role {role_arn}: {e}", file=sys.stderr)
        sys.exit(1)


def get_organization_accounts():
    """Get all accounts in the organization."""
    org_client = boto3.client("organizations")
    accounts = []

    paginator = org_client.get_paginator("list_accounts")
    for page in paginator.paginate():
        for account in page["Accounts"]:
            if account["Status"] == "ACTIVE":
                accounts.append(
                    {
                        "id": account["Id"],
                        "name": account["Name"],
                        "email": account["Email"],
                    }
                )

    return accounts


def get_inspector_members(session, region: str):
    """Get accounts already associated with Inspector in a region."""
    inspector_client = session.client("inspector2", region_name=region)
    members = set()

    try:
        paginator = inspector_client.get_paginator("list_members")
        for page in paginator.paginate():
            for member in page.get("members", []):
                members.add(member["accountId"])
    except ClientError as e:
        # Inspector may not be enabled in this region
        if "not enabled" in str(e).lower() or "AccessDeniedException" in str(e):
            return None  # Signal that Inspector isn't enabled here
        print(f"  Warning: Error listing Inspector members in {region}: {e}")
        return set()

    return members


def get_delegated_admin_account():
    """Get the Inspector delegated admin account ID via Organizations API.

    Uses the Organizations API which works from the management account,
    unlike the Inspector API which only works from the delegated admin itself.
    """
    org_client = boto3.client("organizations")

    try:
        response = org_client.list_delegated_administrators(
            ServicePrincipal="inspector2.amazonaws.com"
        )
        admins = response.get("DelegatedAdministrators", [])
        if admins:
            return admins[0].get("Id")
        return None
    except ClientError as e:
        print(f"Error getting delegated admin: {e}", file=sys.stderr)
        return None


def associate_member(session, account_id: str, region: str) -> bool:
    """Associate a member account with Inspector in a specific region."""
    inspector_client = session.client("inspector2", region_name=region)

    try:
        inspector_client.associate_member(accountId=account_id)
        return True
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code == "ValidationException" and "already associated" in str(e):
            return True  # Already associated
        # Don't print error for each account - we'll summarize at the end
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Enroll organization accounts in Inspector across all regions"
    )
    parser.add_argument(
        "--audit-account-id",
        required=True,
        help="Audit account ID (Inspector delegated admin)",
    )
    parser.add_argument(
        "--role-name",
        default="OrganizationAccountAccessRole",
        help="Role name to assume in audit account",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Actually enroll accounts (default is dry-run)",
    )
    args = parser.parse_args()

    print("Inspector Member Enrollment (All Regions)")
    print("=" * 50)

    # Get current account
    sts = boto3.client("sts")
    current_account = sts.get_caller_identity()["Account"]
    print(f"Running from account: {current_account}")

    # Verify the delegated admin matches the provided audit account
    delegated_admin = get_delegated_admin_account()
    if delegated_admin != args.audit_account_id:
        print(
            "\nError: Provided audit account does not match Inspector delegated admin."
        )
        print(f"  Provided: {args.audit_account_id}")
        print(f"  Delegated admin: {delegated_admin}")
        sys.exit(1)

    print(f"Inspector delegated admin: {delegated_admin}")

    # Assume role into audit account
    print("Assuming role into audit account...")
    audit_session = assume_audit_role(args.audit_account_id, args.role_name)
    print(f"  Successfully assumed {args.role_name}")

    # Get all org accounts (from management account)
    print("Fetching organization accounts...")
    all_accounts = get_organization_accounts()
    # Exclude the audit account (delegated admin can't be associated as a member)
    member_accounts = [a for a in all_accounts if a["id"] != args.audit_account_id]
    print(f"  Found {len(member_accounts)} member accounts (excluding delegated admin)")

    # Get all regions
    regions = get_all_regions()
    print(f"  Scanning {len(regions)} regions...")
    print("")

    # Track enrollment status per region
    region_stats = {}
    total_to_enroll = 0
    total_already_enrolled = 0
    total_enrolled = 0
    regions_not_enabled = []

    for region in regions:
        existing_members = get_inspector_members(audit_session, region)

        if existing_members is None:
            # Inspector not enabled in this region
            regions_not_enabled.append(region)
            continue

        accounts_to_enroll = [
            a for a in member_accounts if a["id"] not in existing_members
        ]
        already_enrolled = len(member_accounts) - len(accounts_to_enroll)

        region_stats[region] = {
            "to_enroll": accounts_to_enroll,
            "already_enrolled": already_enrolled,
            "enrolled": 0,
            "failed": 0,
        }

        total_to_enroll += len(accounts_to_enroll)
        total_already_enrolled += already_enrolled

    # Summary of what needs to be done
    print("Region Summary:")
    if regions_not_enabled:
        print(f"  Inspector not enabled: {len(regions_not_enabled)} regions")
        print(
            f"    ({', '.join(regions_not_enabled[:5])}{'...' if len(regions_not_enabled) > 5 else ''})"
        )

    regions_needing_enrollment = [r for r, s in region_stats.items() if s["to_enroll"]]
    regions_complete = [r for r, s in region_stats.items() if not s["to_enroll"]]

    print(f"  Already complete: {len(regions_complete)} regions")
    print(f"  Needing enrollment: {len(regions_needing_enrollment)} regions")
    print(f"  Total account-region pairs to enroll: {total_to_enroll}")
    print("")

    if total_to_enroll == 0:
        print("All accounts are already enrolled in Inspector across all regions.")
        return

    # Show details of what needs enrollment
    if regions_needing_enrollment:
        print("Regions needing enrollment:")
        for region in sorted(regions_needing_enrollment):
            stats = region_stats[region]
            print(f"  {region}: {len(stats['to_enroll'])} accounts")

    if not args.apply:
        print("\nDry run complete. Use --apply to enroll accounts.")
        return

    # Actually enroll accounts
    print("\nEnrolling accounts...")
    for region in sorted(regions_needing_enrollment):
        stats = region_stats[region]
        accounts = stats["to_enroll"]
        print(f"  {region}: ", end="", flush=True)

        success = 0
        failed = 0
        for account in accounts:
            if associate_member(audit_session, account["id"], region):
                success += 1
            else:
                failed += 1

        stats["enrolled"] = success
        stats["failed"] = failed
        total_enrolled += success

        if failed == 0:
            print(f"{success} enrolled")
        else:
            print(f"{success} enrolled, {failed} failed")

    # Final summary
    print("")
    print("=" * 50)
    print("Enrollment Summary:")
    print(f"  Total enrolled: {total_enrolled}/{total_to_enroll} account-region pairs")

    failed_regions = [r for r, s in region_stats.items() if s["failed"] > 0]
    if failed_regions:
        print(f"  Regions with failures: {', '.join(failed_regions)}")


if __name__ == "__main__":
    main()
