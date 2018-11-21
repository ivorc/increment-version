#!/usr/bin/env python3

import argparse
import configparser
import json
import os
import re
import shutil
import sys
import xml.etree.ElementTree as ET
from types import SimpleNamespace

import boto3
import git


def main():
    args = parse_args()

    aws_session = get_aws_session(args.profile)

    gh_creds = SimpleNamespace(user='kburton')
    gh_creds.token = get_github_token(gh_creds.user, aws_session)

    reinstate_git_folder(gh_creds, args.repo_root)

    # fetch_tags(gh_creds) Needed?

    base_version = extract_root_version(args.version_file)
    print(f"base_version={base_version}")

    last_tag = find_newest_matching_tag(
        args.repo_root, base_version, args.tag_prefix)
    print(f"last_tag={last_tag}")

    next_version = calculate_next_version(base_version, last_tag)
    print(f"next_version={next_version}")

    write_next_version_to_file(args.version_file, next_version)
    print(f"{args.version_file} updated")

    git_tag(args.repo_root, next_version)
    print(f"New tag {next_version} created")


def parse_args():
    parser = argparse.ArgumentParser(
        description='Increment the semantic version in git and file')
    parser.add_argument('--profile', dest='profile', default=None,
                        help='AWS profile name for parameter store access')
    parser.add_argument('repo_root', help='Root folder of the repository')
    parser.add_argument(
        'version_file', help='File containing version to update')
    parser.add_argument(
        '--tag_prefix', dest='tag_prefix', default="", help='String prefix to versioning tags')
    return parser.parse_args()


def get_aws_session(aws_profile):
    config = configparser.ConfigParser()
    home = os.path.expanduser("~")
    config.read(home + '/.aws/credentials')
    role_arn = config.get(aws_profile, 'role_arn')
    mfa_serial = config.get(aws_profile, 'mfa_serial')

    mfa_TOTP = input(
        f"Authenticating for [{aws_profile}] role. Enter MFA code: ")

    client = boto3.client('sts')

    response = client.assume_role(
        RoleArn=role_arn,
        RoleSessionName='mysession',
        DurationSeconds=3600,
        SerialNumber=mfa_serial,
        TokenCode=mfa_TOTP,
    )

    return boto3.session.Session(
        aws_access_key_id=response['Credentials']['AccessKeyId'],
        aws_secret_access_key=response['Credentials']['SecretAccessKey'],
        aws_session_token=response['Credentials']['SessionToken'])


def get_github_token(github_user, aws_session):
    ssm = aws_session.client('ssm')
    parameter = ssm.get_parameter(
        Name='/api/github-oauth-token', WithDecryption=True)

    return parameter['Parameter']['Value']


def get_commit():
    commit = os.getenv("CODEBUILD_RESOLVED_SOURCE_VERSION",
                       os.getenv("CODEBUILD_SOURCE_VERSION"))
    if commit is None:
        raise("Could not determine commit to checkout: Neither CODEBUILD_RESOLVED_SOURCE_VERSION or CODEBUILD_SOURCE_VERSION set.")
    return commit


def reinstate_git_folder(gh_creds, repo_root):
    try:
        git.Repo(repo_root)
        print(".git folder already exists, so skipping reinstate it")
        return
    except git.exc.InvalidGitRepositoryError:
        print("Reinstating git folder")
        pass

    commit = get_commit()

    tmp_src = f"{repo_root}/../tmp-src"
    if not os.path.exists(tmp_src):
        os.makedirs(tmp_src)
    new_clone = git.Repo.clone_from(
        f"https://{gh_creds.user}:{gh_creds.token}@github.com/emisgroup/emiscloud-appointments.git", tmp_src)
    new_clone.git.checkout(commit)
    shutil.move(f"{tmp_src}/.git", repo_root)


# def fetch_tags(gh_creds, repo_root):
#     git.Repo(repo_root).git.fetch()

def extract_major_minor(full_version):
    pattern = re.compile('([0-9]+\.[0-9]+).*')

    match_iter = re.finditer(pattern, full_version)
    first_match = next(match_iter)
    return first_match.groups()[0]


def find_version_node_csproj(version_file):
    tree = ET.parse(version_file)
    root = tree.getroot()
    return root.find("./PropertyGroup/Version"), tree


def extract_root_version_csproj(version_file):
    version_node, _ = find_version_node_csproj(version_file)
    return extract_major_minor(version_node.text)


def extract_root_version_npm(version_file):
    with open(version_file, encoding='utf-8') as f:
        contents = json.load(f)

    return extract_major_minor(contents["version"])


def extract_root_version(version_file):
    if version_file.endswith(".csproj"):
        return extract_root_version_csproj(version_file)
    elif version_file.endswith("package.json"):
        return extract_root_version_npm(version_file)
    else:
        raise(f"Unrecognised version file format {version_file}")


def extract_minor_version_from_tag(tag):
    pattern = re.compile('[0-9]+\.[0-9]+\.([0-9]+)')

    match_iter = re.finditer(pattern, tag)
    first_match = next(match_iter)
    return first_match.groups()[0]


def find_newest_matching_tag(repo_root, base_version, tag_prefix):
    tags = git.Repo(repo_root).tags
    filtered_tags = [t for t in tags if t.path.startswith(
        f"refs/tags/{tag_prefix}{base_version}")]
    if filtered_tags:
        # Find max by zero padded minor version
        last_tag = max(
            filtered_tags, key=lambda t: f'{extract_minor_version_from_tag(str(t)):0>8}')
        return str(last_tag)
    else:
        return None


def calculate_next_version(base_version, last_tag):
    if last_tag is None:
        return f"{base_version}.0"
    else:
        return f"{base_version}.{1+int(extract_minor_version_from_tag(last_tag))}"


def write_next_version_to_csproj(version_file, next_version):
    version_node, tree = find_version_node_csproj(version_file)
    version_node.text = next_version
    tree.write(version_file)


def write_next_version_to_npm(version_file, next_version):
    with open(version_file, encoding='utf-8') as f:
        contents = json.load(f)

    contents["version"] = next_version

    with open(f"{version_file}.new", "w") as f:
        json.dump(contents, f, indent=2)


def write_next_version_to_file(version_file, next_version):
    if version_file.endswith(".csproj"):
        return write_next_version_to_csproj(version_file, next_version)
    elif version_file.endswith("package.json"):
        return write_next_version_to_npm(version_file, next_version)
    else:
        raise(f"Unrecognised version file format {version_file}")


def git_tag(repo_root, tag):
    repo = git.Repo(repo_root)
    tag_object = repo.create_tag(tag)
    repo.remotes.origin.push(tag_object)


if __name__ == '__main__':
    main()
