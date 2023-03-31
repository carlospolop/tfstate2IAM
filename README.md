# Tfstate2IAM

**Tfstate2IAM** is a Python tool that analyzes **AWS Tfsate files from S3 to extract groups, users, roles and policies** of the account. The tool will **parse every `.tfstate` from the indicated bucket**.

This is useful for red teamers that have **read access over tfstates files and wants to have more info about the permissions** of the roles and users but **doesn't have read access over IAM**.

## Installation

```sh
git clone https://github.com/carlospolop/Tfstate2IAM
cd Tfstate2IAM
pip install -r requirements.txt
python3 tfstate2IAM.py --prefix <PREFIX_INSIDE_BUCKET> --bucket-name <BUCKET_NAME> --profile <PROFILE> [--threads THREADS]
```