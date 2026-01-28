#!/usr/bin/env python3
"""
Default VPC cleanup script for AWS Organization.
Removes default VPCs from all accounts in the organization across all regions.
"""

import sys

import boto3
from botocore.exceptions import ClientError


def get_all_regions() -> list:
    """Get all active AWS regions."""
    ec2_client = boto3.client("ec2", region_name="us-east-1")
    regions = ec2_client.describe_regions(AllRegions=False)["Regions"]
    return [r["RegionName"] for r in regions]


def get_organization_accounts() -> list:
    """Get all accounts in the organization."""
    org_client = boto3.client("organizations", region_name="us-east-1")
    accounts = []

    try:
        paginator = org_client.get_paginator("list_accounts")
        for page in paginator.paginate():
            for account in page["Accounts"]:
                if account["Status"] == "ACTIVE":
                    accounts.append(
                        {
                            "id": account["Id"],
                            "name": account["Name"],
                        }
                    )
    except ClientError as e:
        print(f"Error listing accounts: {e}")

    return accounts


def assume_role(account_id: str, region: str) -> boto3.Session:
    """Assume OrganizationAccountAccessRole in target account."""
    sts_client = boto3.client("sts", region_name=region)
    role_arn = f"arn:aws:iam::{account_id}:role/OrganizationAccountAccessRole"

    try:
        response = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName="org-baseline-vpc-cleanup",
            DurationSeconds=900,
        )
        credentials = response["Credentials"]
        return boto3.Session(
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"],
            region_name=region,
        )
    except ClientError:
        return None


def delete_default_vpc(session: boto3.Session, region: str) -> dict:
    """Delete the default VPC in a region.

    Returns dict with:
        - deleted: True if VPC was deleted
        - skipped: True if VPC has dependencies (not an error)
        - error: Error message if actual error occurred
        - had_vpc: True if a default VPC existed
    """
    result = {
        "region": region,
        "deleted": False,
        "skipped": False,
        "error": None,
        "had_vpc": False,
    }

    ec2 = session.client("ec2", region_name=region)

    try:
        # Find default VPC
        vpcs = ec2.describe_vpcs(Filters=[{"Name": "is-default", "Values": ["true"]}])[
            "Vpcs"
        ]

        if not vpcs:
            return result

        result["had_vpc"] = True
        vpc_id = vpcs[0]["VpcId"]

        # Check if VPC is in use by looking for ENIs
        enis = ec2.describe_network_interfaces(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
        )["NetworkInterfaces"]

        if enis:
            # VPC has active resources - skip to avoid partial cleanup
            result["skipped"] = True
            return result

        # Delete Internet Gateways
        igws = ec2.describe_internet_gateways(
            Filters=[{"Name": "attachment.vpc-id", "Values": [vpc_id]}]
        )["InternetGateways"]

        for igw in igws:
            igw_id = igw["InternetGatewayId"]
            try:
                ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
                ec2.delete_internet_gateway(InternetGatewayId=igw_id)
            except ClientError as e:
                if "InvalidInternetGatewayID.NotFound" not in str(e):
                    if "DependencyViolation" in str(e):
                        pass  # Continue trying other resources
                    else:
                        raise

        # Delete Subnets
        subnets = ec2.describe_subnets(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
        )["Subnets"]

        for subnet in subnets:
            subnet_id = subnet["SubnetId"]
            try:
                ec2.delete_subnet(SubnetId=subnet_id)
            except ClientError as e:
                if "InvalidSubnetID.NotFound" not in str(e):
                    if "DependencyViolation" in str(e):
                        pass  # Continue trying other resources
                    else:
                        raise

        # Delete non-default Security Groups
        sgs = ec2.describe_security_groups(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
        )["SecurityGroups"]

        for sg in sgs:
            if sg["GroupName"] != "default":
                try:
                    ec2.delete_security_group(GroupId=sg["GroupId"])
                except ClientError as e:
                    if "InvalidGroup.NotFound" not in str(e):
                        if "DependencyViolation" in str(e):
                            pass  # Continue trying other resources
                        else:
                            raise

        # Delete non-main Route Tables
        rts = ec2.describe_route_tables(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
        )["RouteTables"]

        for rt in rts:
            # Check if this is the main route table
            is_main = any(
                assoc.get("Main", False) for assoc in rt.get("Associations", [])
            )
            if not is_main:
                try:
                    ec2.delete_route_table(RouteTableId=rt["RouteTableId"])
                except ClientError as e:
                    if "InvalidRouteTableID.NotFound" not in str(e):
                        if "DependencyViolation" in str(e):
                            pass  # Continue trying other resources
                        else:
                            raise

        # Delete non-default Network ACLs
        nacls = ec2.describe_network_acls(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
        )["NetworkAcls"]

        for nacl in nacls:
            if not nacl.get("IsDefault", False):
                try:
                    ec2.delete_network_acl(NetworkAclId=nacl["NetworkAclId"])
                except ClientError as e:
                    if "InvalidNetworkAclID.NotFound" not in str(e):
                        if "DependencyViolation" in str(e):
                            pass  # Continue trying other resources
                        else:
                            raise

        # Delete the VPC
        ec2.delete_vpc(VpcId=vpc_id)
        result["deleted"] = True

    except ClientError as e:
        if "DependencyViolation" in str(e):
            # VPC has active dependencies - mark as skipped, not error
            result["skipped"] = True
        else:
            result["error"] = str(e)

    return result


def cleanup_account_vpcs(account: dict, regions: list) -> dict:
    """Clean up default VPCs for a single account across all regions."""
    account_result = {
        "account_id": account["id"],
        "account_name": account["name"],
        "regions": {},
        "success": True,
        "has_skipped": False,
    }

    # Get current account ID to skip management account
    sts = boto3.client("sts")
    current_account = sts.get_caller_identity()["Account"]

    for region in regions:
        # For management account, use default credentials
        if account["id"] == current_account:
            session = boto3.Session(region_name=region)
        else:
            session = assume_role(account["id"], region)
            if session is None:
                account_result["regions"][region] = {
                    "deleted": False,
                    "skipped": False,
                    "error": "Could not assume role",
                }
                account_result["success"] = False
                continue

        result = delete_default_vpc(session, region)
        account_result["regions"][region] = result

        if result.get("error"):
            account_result["success"] = False
        if result.get("skipped"):
            account_result["has_skipped"] = True

    return account_result


def main():
    """Main cleanup function."""
    print("=" * 50)
    print("  Default VPC Cleanup")
    print("=" * 50)
    print("")

    # Get all regions
    print("Getting AWS regions...")
    regions = get_all_regions()
    print(f"Found {len(regions)} regions")
    print("")

    # Get all accounts
    print("Getting organization accounts...")
    accounts = get_organization_accounts()
    print(f"Found {len(accounts)} active accounts")
    print("")

    if not accounts:
        print("No accounts found. Is this the management account of an organization?")
        return 1

    # Process accounts
    total_deleted = 0
    total_skipped = 0
    total_errors = 0

    for account in accounts:
        print(f"Processing {account['name']} ({account['id']})...")

        result = cleanup_account_vpcs(account, regions)

        deleted_regions = []
        skipped_regions = []
        error_regions = []

        for region, region_result in result["regions"].items():
            if region_result.get("deleted"):
                deleted_regions.append(region)
                total_deleted += 1
            elif region_result.get("skipped"):
                skipped_regions.append(region)
                total_skipped += 1
            elif region_result.get("error"):
                error_regions.append(f"{region}: {region_result['error']}")
                total_errors += 1

        if deleted_regions:
            print(f"  Deleted default VPCs in: {', '.join(deleted_regions)}")
        if skipped_regions:
            print(f"  Skipped (has dependencies): {', '.join(skipped_regions)}")
        if error_regions:
            for err in error_regions:
                print(f"  Error in {err}")
        if not deleted_regions and not skipped_regions and not error_regions:
            print("  No default VPCs found")

    print("")
    print("=" * 50)
    print("  Summary")
    print("=" * 50)
    print(f"  Accounts processed: {len(accounts)}")
    print(f"  Default VPCs deleted: {total_deleted}")
    print(f"  Skipped (dependencies): {total_skipped}")
    print(f"  Errors: {total_errors}")
    print("")

    if total_errors > 0:
        print("Some VPCs had errors (not dependency-related).")
        return 1

    if total_skipped > 0:
        print(f"Completed! {total_skipped} VPC(s) skipped due to active dependencies.")
        print("These will be cleaned up in follow-up processes.")
        return 0

    print("Default VPC cleanup complete!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
