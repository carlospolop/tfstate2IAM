import argparse
import boto3
import json
from typing import Dict, Any, Set
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed

# ANSI color escape codes
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
END = '\033[0m'

ALL_POLICIES: Dict[str, Dict] = {}
ALL_GROUPS: Dict[str, Dict] = {}
ALL_USERS: Set[str] = set([])
ALL_ROLES: Dict[str, set] = {}

def get_s3_client(profile: str):
    """Create an S3 client using the specified profile."""
    session = boto3.Session(profile_name=profile)
    return session.client('s3')

def download_tfstate_file(s3_client, bucket: str, key: str, local_path: str):
    """Download the Terraform state file from the specified S3 bucket and key to a local path."""
    s3_client.download_file(bucket, key, local_path)

def process_tfstate_file(file_path: str):
    """Extract role and user ARNs, and their associated policies, from the downloaded Terraform state file."""
    global ALL_POLICIES, ALL_GROUPS, ALL_USERS, ALL_ROLES

    if not file_path.endswith(".tfstate"):
        return

    with open(file_path, 'rt', encoding='utf-8') as file:
        data = json.load(file)
        for resource in data.get('resources', []):
            if 'registry.terraform.io/hashicorp/aws' in str(resource.get('provider', "")):

                # AWS role & user attached policies
                if resource['type'] in ('aws_iam_role_policy_attachment', 'aws_iam_user_policy_attachment', 'aws_iam_group_policy_attachment'):
                    for instance in resource['instances']:
                        policy_arn = instance['attributes']['policy_arn']

                        if resource['type'] == 'aws_iam_role_policy_attachment':
                            principal = instance['attributes']['role']
                            if not principal in ALL_ROLES:
                                ALL_ROLES[principal] = ""

                        elif resource['type'] == 'aws_iam_user_policy_attachment':
                            principal = instance['attributes']['user']
                            ALL_USERS.update(set([principal]))

                        else:
                            principal = instance['attributes']['group']
                            ALL_GROUPS.update(set([principal]))

                        if policy_arn in ALL_POLICIES:
                            ALL_POLICIES[policy_arn]["principals"].update(set([principal]))
                        else:
                            ALL_POLICIES[policy_arn]= {"principals": [principal], "permissions": ""}

                # AWS role inline policy (always new)
                elif resource['type'] in ('aws_iam_role_policy', 'aws_iam_user_policy', 'aws_iam_group_policy'):
                    for instance in resource['instances']:
                        policy_id = instance['attributes']['id']
                        policy = instance['attributes']['policy']

                        if resource['type'] == 'aws_iam_role_policy':
                            principal = instance['attributes']['role']
                            if not principal in ALL_ROLES:
                                ALL_ROLES[principal] = ""

                        elif resource['type'] == 'aws_iam_user_policy':
                            principal = instance['attributes']['user']
                            ALL_USERS.update(set([principal]))

                        else:
                            principal = instance['attributes']['group']
                            ALL_GROUPS.update(set([principal]))

                        ALL_POLICIES[policy_id]= {"principals": set([principal]), "permissions": policy}

                # Permissions of an custom attached policy
                elif resource['type'] == 'aws_iam_policy':
                    for instance in resource['instances']:
                        policy_arn = instance['attributes']['arn']
                        policy = instance['attributes']['policy']
                        
                        if policy_arn in ALL_POLICIES:
                            ALL_POLICIES[policy_arn]["permissions"] = policy
                        else:
                            ALL_POLICIES[policy_arn]= {"principals": set([]), "permissions": policy}
                
                # Group memberships
                elif resource['type'] == 'aws_iam_group_membership':
                    for instance in resource['instances']:
                        group = instance['attributes']['group']
                        users = instance['attributes']['users']

                        ALL_GROUPS.update(set([group]))
                        
                        if group in ALL_GROUPS:
                            ALL_GROUPS[group]["users"].update(set(users))
                        else:
                            ALL_GROUPS[group]= {"users": set(users)}
                        
                        for user in users:
                            ALL_USERS.update(set([user]))
                
                # User memberships
                elif resource['type'] == 'aws_iam_user_group_membership':
                    for instance in resource['instances']:
                        groups = instance['attributes']['groups']
                        user = instance['attributes']['user']

                        ALL_USERS.update(set([user]))
                        
                        for group in groups:
                            ALL_GROUPS.update(set([group]))
                            if group in ALL_GROUPS:
                                ALL_GROUPS[group]["users"].update(set([user]))
                            else:
                                ALL_GROUPS[group]= {"users": set([user])}
                            
                # Role creation
                elif resource['type'] == 'aws_iam_role':
                    for instance in resource['instances']:
                        role = instance['attributes']['arn'].split("/")[-1]
                        assume_policy = instance['attributes']['assume_role_policy']
                        ALL_ROLES[role] = assume_policy
                
                # User creation
                elif resource['type'] == 'aws_iam_user':
                    for instance in resource['instances']:
                        user = instance['attributes']['arn'].split("/")[-1]
                        ALL_USERS.update(set([user]))
                
                # Group creation
                elif resource['type'] == 'aws_iam_group':
                    for instance in resource['instances']:
                        group = instance['attributes']['arn'].split("/")[-1]
                        ALL_GROUPS.update(set([group]))



def get_all_keys(s3_client, bucket_name: str, prefix: str) -> Dict[str, Any]:
    """List all objects with the specified prefix in the S3 bucket."""
    tfstate_files = []
    paginator = s3_client.get_paginator('list_objects_v2')

    for page in paginator.paginate(Bucket=bucket_name, Prefix=prefix):
        if 'Contents' in page:
            tfstate_files.extend(page['Contents'])
            print("Found {} tfstate files".format(len(tfstate_files)), end='\r')
    
    print()

    return tfstate_files

def process_tfstate_object(s3_client, bucket_name: str, tfstate_obj: Dict[str, Any]):
    """Download and process each Terraform state file."""
    tfstate_key = tfstate_obj['Key']
    if not tfstate_key.endswith('.tfstate'):
        return

    with tempfile.NamedTemporaryFile() as temp_file:
        download_tfstate_file(s3_client, bucket_name, tfstate_key, temp_file.name)
        process_tfstate_file(temp_file.name)

def print_roles():
    """Print all roles with their associated assume role policies."""
    print(f"\n{YELLOW}ALL ROLES{END}")
    for role, assume_policy in ALL_ROLES.items():
        print(f"{BLUE}- {role}:{END} {assume_policy}")

def print_groups():
    """Print all groups with their associated users."""
    print(f"\n{YELLOW}ALL GROUPS{END}")
    for group, info in ALL_GROUPS.items():
        users = ", ".join(info["users"])
        print(f"{BLUE}- {group}:{END}")
        print(f"  {GREEN}Users:{END} {users}")

def print_users():
    """Print all users."""
    print(f"\n{YELLOW}ALL USERS{END}")
    for user in ALL_USERS:
        print(f"{BLUE}- {user}{END}")

def print_policies():
    """Print all policies with their associated principals and permissions."""
    print(f"\n{YELLOW}ALL POLICIES{END}")
    for policy_arn, info in ALL_POLICIES.items():
        principals = ", ".join(info["principals"])
        permissions = info["permissions"]
        print(f"{BLUE}- {policy_arn}:{END}")
        print(f"  {RED}Principals:{END} {principals}")
        print(f"  {GREEN}Permissions:{END}\n{permissions}")

def main():
    global ALL_POLICIES

    parser = argparse.ArgumentParser(description='Analyze Terraform state files for role and user policies')
    parser.add_argument('--prefix', required=True, help='The S3 prefix for Terraform state files')
    parser.add_argument('--bucket-name', required=True, help='The S3 bucket name containing Terraform state files')
    parser.add_argument('--profile', required=True, help='The AWS profile to use for accessing the S3 bucket')
    parser.add_argument('--threads', type=int, default=20, help='The number of threads to use for processing Terraform state files (default: 20)')
    args = parser.parse_args()

    s3_client = get_s3_client(args.profile)

    tfstate_files = get_all_keys(s3_client, args.bucket_name, args.prefix)

    # Use ThreadPoolExecutor to process Terraform state files with the specified number of threads
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [executor.submit(process_tfstate_object, s3_client, args.bucket_name, tfstate_obj) for tfstate_obj in tfstate_files]
        for future in as_completed(futures):
            future.result()

    # Print all
    print_roles()
    print_users()
    print_groups()
    print_policies()


if __name__ == '__main__':
    main()