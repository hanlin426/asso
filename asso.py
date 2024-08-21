#!/usr/bin/env python3

import argparse
import argcomplete
import hashlib
import json
import os
import re
import subprocess
from subprocess import PIPE, Popen, STDOUT
import sys
from configparser import ConfigParser
from datetime import datetime, timedelta
from pathlib import Path
import yaml

import boto3
import inquirer
from dateutil.parser import parse
from dateutil.tz import UTC, tzlocal

AWS_CONFIG_DIR = f'{Path.home()}/.aws'
AWS_CONFIG_PATH = f'{Path.home()}/.aws/config'
AWS_CREDENTIAL_PATH = f'{Path.home()}/.aws/credentials'
AWS_SSO_CACHE_PATH = f'{Path.home()}/.aws/sso/cache'
CURRENT_REGION = os.getenv('AWS_REGION')
AWS_DEFAULT_REGION = CURRENT_REGION
AWS_ECR_ACCOUNT = os.getenv('AWS_ECR_ACCOUNT')
AWS_ECR_REGION = os.getenv('AWS_ECR_REGION')

if not CURRENT_REGION:
    current_session = boto3.session.Session()
    CURRENT_REGION = current_session.region_name

if not CURRENT_REGION:
    CURRENT_REGION = 'us-west-2'

if not AWS_ECR_REGION:
    AWS_ECR_REGION = 'us-west-2'

if not os.path.exists(AWS_CONFIG_DIR):
    config_dir = Path(AWS_CONFIG_DIR)
    config_dir.mkdir(parents=True)

def main():
    parser = argparse.ArgumentParser(description='Retrieves AWS credentials from SSO for use with CLI/Boto3 apps.')
    subparsers = parser.add_subparsers()

    parser.add_argument('-l',
        action='store_true',
        help='aws sso login.')
    parser.add_argument('-c',
        action='store_true',
        help='aws sso config.')
    parser.add_argument('-s',
        nargs='*',
        help='aws sso switch account.')
    parser.add_argument('-g',
        action='store_true',
        help='aws sso logout.')
    parser.add_argument('-i',
        action='store_true',
        help='check aws session.')


    parser_ec2 = subparsers.add_parser('ec2')
    parser_ec2_sub = parser_ec2.add_subparsers()
    parser_ec2_search = parser_ec2_sub.add_parser('search',
                        help='search out ec2 instance id by keyword: ip, name')
    parser_ec2_search.add_argument('ec2')
    parser_ec2_search.set_defaults(func=_ec2_search)

    parser_ec2_login = parser_ec2_sub.add_parser('login',
                        help='ssm login into ec2.')
    parser_ec2_login.add_argument('ec2')
    parser_ec2_login.set_defaults(func=_ec2_login)


    parser_sm = subparsers.add_parser('sm')
    parser_sm_sub = parser_sm.add_subparsers()
    parser_sm_search = parser_sm_sub.add_parser('search',
                        help='search secrets manager')
    parser_sm_search.add_argument('secret')
    parser_sm_search.set_defaults(func=_sm_search)

    parser_sm_get = parser_sm_sub.add_parser('get',
                        help='get secrets manager')
    parser_sm_get.add_argument('secret')
    parser_sm_get.set_defaults(func=_sm_get)

    parser_sm_create = parser_sm_sub.add_parser('create',
                        help='create secrets manager')
    parser_sm_create.add_argument('create', action='store_true')
    parser_sm_create.set_defaults(func=_sm_create)

    parser_sm_update = parser_sm_sub.add_parser('update',
                        help='update secrets manager')
    parser_sm_update.add_argument('secret')
    parser_sm_update.set_defaults(func=_sm_update)

    parser_sm_delete = parser_sm_sub.add_parser('delete',
                        help='delete secrets manager')
    parser_sm_delete.add_argument('secret')
    parser_sm_delete.set_defaults(func=_sm_delete)

    parser_ssm = subparsers.add_parser('ssm')
    parser_ssm_sub = parser_ssm.add_subparsers()
    parser_ssm_search = parser_ssm_sub.add_parser('search',
                        help='search parameters')
    parser_ssm_search.add_argument('parameter')
    parser_ssm_search.set_defaults(func=_ssm_search)

    parser_ssm_get = parser_ssm_sub.add_parser('get',
                        help='get parameter value')
    parser_ssm_get.add_argument('parameter')
    parser_ssm_get.set_defaults(func=_ssm_get)

    parser_ssm_delete = parser_ssm_sub.add_parser('delete',
                        help='delete parameter value')
    parser_ssm_delete.add_argument('parameter')
    parser_ssm_delete.set_defaults(func=_ssm_delete)

    parser_image = subparsers.add_parser('image')
    parser_image_sub = parser_image.add_subparsers()
    parser_image_list = parser_image_sub.add_parser('list',
                        help='list service images.')
    parser_image_list.add_argument('service')
    parser_image_list.set_defaults(func=_image_list)

    parser_image_pull = parser_image_sub.add_parser('pull',
                        help='pull service image.')
    parser_image_pull.add_argument('image',
                        help='image full name.')
    parser_image_pull.set_defaults(func=_image_pull)

    parser_image_cve = parser_image_sub.add_parser('cve',
                        help='get image cve report.')
    parser_image_cve.add_argument('service',
                        help='service name.')
    parser_image_cve.add_argument('tag',
                        help='service image tag')
    parser_image_cve.set_defaults(func=_image_cve)

    parser_image_run = parser_image_sub.add_parser('run',
                        help='run service image with envs injected. eg: awsso image run test-server a1b2c3d4 [8080]')
    parser_image_run.add_argument('service',
                        help='service name.')
    parser_image_run.add_argument('tag', nargs='*',
                        help='service image tag [port]')
    parser_image_run.set_defaults(func=_image_run)

    argcomplete.autocomplete(parser)
    args = parser.parse_args()

    if len(sys.argv)==1:
        parser.print_help()
    if len(sys.argv) == 3 and sys.argv[1] == '-s':
        _sso_switch(sys.argv[2])
    if len(sys.argv) == 2 and sys.argv[1] in ('-l', '-c', '-s', '-g', '-i'):
        if sys.argv[1] == '-l':
            _sso_login()
        if sys.argv[1] == '-c':
            _sso_config()
        if sys.argv[1] == '-s':
            _sso_switch()
        if sys.argv[1] == '-g':
            _sso_logout()
        if sys.argv[1] == '-i':
            _sso_session_check()
    if len(sys.argv) == 2 and sys.argv[1] in subparsers.choices:
        print(subparsers.choices[sys.argv[1]].format_help())

    if hasattr(args, 'func'):
        if args.func == _ec2_search:
            _ec2_search(args.ec2)
        if args.func == _ec2_login:
            _ec2_login(args.ec2)
        if args.func == _sm_search:
            _sm_search(args.secret)
        if args.func == _sm_get:
            _sm_get(args.secret)
        if args.func == _sm_create:
            _sm_create()
        if args.func == _sm_update:
            _sm_update(args.secret)
        if args.func == _sm_delete:
            _sm_delete(args.secret)
        if args.func == _ssm_search:
            _ssm_search(args.parameter)
        if args.func == _ssm_get:
            _ssm_get(args.parameter)
        if args.func == _ssm_delete:
            _ssm_delete(args.parameter)
        if args.func == _image_list:
            _image_list(args.service)
        if args.func == _image_pull:
            _image_pull(args.image)
        if args.func == _image_cve:
            _image_cve(args.service, args.tag)
        if args.func == _image_run:
            _image_run(args.service, args.tag)


def _sso_config():
    sso_config()
    sys.exit()

def _sso_switch(env=''):
    if not env:
        profile = _add_prefix(_select_profile())
    else:
        profile = 'profile ' + env
    try:
        profile_opts = _get_aws_profile(profile)
    except:
        print('The profile: {} is not found.'.format(env))
        sys.exit(1)
    profile_name = profile.split(' ')[1]
    source_value = '''

export AWS_ENVS={0}
export AWS_REGION={1}
export AWS_ACCOUNT={2}
export AWS_PROFILE={3}
export AWS_DEFAULT_REGION={1}
export PS1=\\"{0} \$ \\"
    '''.format(profile_name.split('_')[0], profile_opts['region'], profile_opts['sso_account_id'], profile_name)
    os.system('echo "{}" > ~/.aws/env'.format(source_value))
    output = '''
Please execute the following command:

\033[33m
source ~/.aws/env
\033[0m
'''
    print(output)
    _set_profile_credentials(profile)

def _sso_logout():
    select_one = True
    profile = _add_prefix(_select_profile(select_one))
    sso_logout(profile)

def _sso_session_check():
    subprocess.run(['aws', 'sts', 'get-caller-identity'],
                       stderr=sys.stderr,
                       stdout=sys.stdout,
                       check=True)

def _sso_login():
    select_one = True
    profile = _add_prefix(_select_profile(select_one))
    sso_auth(profile)
    _set_profile_credentials(profile)

def _set_profile_credentials(profile_name, use_default=False):
    profile_opts = _get_aws_profile(profile_name)
    cache_login = _get_sso_cached_login(profile_opts)
    credentials = _get_sso_role_credentials(profile_opts, cache_login)

    _store_aws_credentials('default', profile_opts, credentials)
    _copy_to_default_profile(profile_name)


def _get_aws_profile(profile_name):
    config = _read_config(AWS_CONFIG_PATH)
    profile_opts = config.items(profile_name)
    profile = dict(profile_opts)
    return profile


def _get_sso_cached_login(profile):

    cache = hashlib.sha1(profile["sso_start_url"].encode("utf-8")).hexdigest()
    sso_cache_file = f'{AWS_SSO_CACHE_PATH}/{cache}.json'

    if not Path(sso_cache_file).is_file():
        print('Current cached SSO login is invalid/missing. Please login with the command: asso -l')

    else:
        data = _load_json(sso_cache_file)
        now = datetime.now().astimezone(UTC)
        expires_at = parse(data['expiresAt']).astimezone(UTC)

        if data.get('region') != profile['sso_region']:
            print('SSO authentication region in cache does not match region defined in profile')

        if now > expires_at:
            print('SSO credentials have expired. Please re-login.')

        if (now + timedelta(minutes=15)) >= expires_at:
            print('Your current SSO credentials will expire in less than 15 minutes!')

        print('Found credentials. Valid until {}'.format(expires_at.astimezone(tzlocal())))
        return data


def _get_sso_role_credentials(profile, login):

    client = boto3.client('sso', region_name=profile['sso_region'])
    response = client.get_role_credentials(
        roleName=profile['sso_role_name'],
        accountId=profile['sso_account_id'],
        accessToken=login['accessToken'],
    )

    expires = datetime.utcfromtimestamp(response['roleCredentials']['expiration'] / 1000.0).astimezone(UTC)
    print('Got session token. Valid until {}'.format(expires.astimezone(tzlocal())))

    return response["roleCredentials"]


def _store_aws_credentials(profile_name, profile_opts, credentials):

    region = profile_opts.get("region", AWS_DEFAULT_REGION)
    config = _read_config(AWS_CREDENTIAL_PATH)

    if config.has_section(profile_name):
        config.remove_section(profile_name)

    config.add_section(profile_name)
    config.set(profile_name, "region", region)
    config.set(profile_name, "aws_access_key_id", credentials["accessKeyId"])
    config.set(profile_name, "aws_secret_access_key ", credentials["secretAccessKey"])
    config.set(profile_name, "aws_session_token", credentials["sessionToken"])

    _write_config(AWS_CREDENTIAL_PATH, config)


def _copy_to_default_profile(profile_name):

    config = _read_config(AWS_CONFIG_PATH)

    if config.has_section('default'):
        config.remove_section('default')

    config.add_section('default')

    for key, value in config.items(profile_name):
        config.set('default', key, value)

    _write_config(AWS_CONFIG_PATH, config)


def _select_profile(select_one=False):
    config = _read_config(AWS_CONFIG_PATH)

    profiles = []
    for section in config.sections():
        profiles.append(str(section).replace('profile ', ''))
    profiles.sort()
    if select_one is True:
        return profiles.pop()
    try:
        profiles.pop(profiles.index('default'))
    except:
        pass

    questions = [
        inquirer.List(
            'name',
            message='Please select an AWS config profile',
            choices=profiles
        ),
    ]
    answer = inquirer.prompt(questions)
    return answer['name'] if answer else sys.exit(1)

def _get_sso_info(config):
    for s in config.sections():
        sso_start_url = config.get(s, 'sso_start_url')
        sso_region = config.get(s, 'sso_region')
        if sso_start_url and sso_region:
            return {'sso_start_url': sso_start_url, 'sso_region': sso_region}
    return {}



def _gen_config_file(config):
    sso_info = _get_sso_info(config)
    dir = os.path.expanduser(AWS_SSO_CACHE_PATH)
    json_files = [pos_json for pos_json in os.listdir(dir) if pos_json.endswith('.json')]

    for json_file in json_files :
        path = dir + '/' + json_file
        with open(path) as file :
            data = json.load(file)
            if 'accessToken' in data:
                accessToken = data['accessToken']

    client = boto3.client('sso',region_name=CURRENT_REGION)
    r = client.list_accounts(accessToken=accessToken)
    if r.get('ResponseMetadata').get('HTTPStatusCode') == 200:
        for account in r.get('accountList'):
            accountId = account.get('accountId')
            account_name = account.get('accountName')
            r1 = client.list_account_roles(
                accessToken=accessToken,
                accountId=accountId)
            if r1.get('ResponseMetadata').get('HTTPStatusCode') == 200:
                for role in r1.get('roleList'):
                    role = role.get('roleName')
                    p_name = f'profile {account_name}_{role}'
                    if not config.has_section(p_name):
                        config.add_section(p_name)
                    config.set(p_name, 'sso_start_url', sso_info.get('sso_start_url'))
                    config.set(p_name, 'sso_region', sso_info.get('sso_region'))
                    config.set(p_name, 'sso_account_id', accountId)
                    config.set(p_name, 'sso_role_name', role)
                    config.set(p_name, 'region', CURRENT_REGION)
                    config.set(p_name, 'output', 'json')
            else:
                print('auth error, please check your aws sso config file')
                return False
        _write_config(AWS_CONFIG_PATH, config)
    else:
        print('auth error, please check your aws sso config file')
        return False

def sso_config():
    p = subprocess.run(['aws', 'configure', 'sso'],
                   stdin=sys.stderr, stdout=sys.stdout, check=True)

    config = _read_config(AWS_CONFIG_PATH)

    if os.getenv('AWS_PROFILE'):
        os_section = 'profile ' + os.getenv('AWS_PROFILE')
        try:
            config.add_section(os_section)
        except:
            pass
    _gen_config_file(config)

def sso_auth(profile):
    subprocess.run(['aws', 'sso', 'login', '--profile', str(profile).replace('profile ', '')],
                   stderr=sys.stderr,
                   stdout=sys.stdout,
                   check=True)

def sso_logout(profile):
    subprocess.run(['aws', 'sso', 'logout', '--profile', str(profile).replace('profile ', '')],
                   stderr=sys.stderr,
                   stdout=sys.stdout,
                   check=True)


def _add_prefix(name):
    return f'profile {name}' if name != 'default' else 'default'


def _read_config(path):
    config = ConfigParser()
    config.read(path)
    return config


def _write_config(path, config):
    with open(path, 'w') as destination:
        config.write(destination)


def _load_json(path):
    try:
        with open(path) as context:
            return json.load(context)
    except ValueError:
        pass  # skip invalid json

def _ec2_search(keyword):
    ec2 = boto3.resource('ec2', region_name=CURRENT_REGION)
    filters = [{'Name':'tag:Name', 'Values': ['*{}*'.format(keyword)]}]
    instances = ec2.instances.filter(Filters=filters)
    i_list = []
    for i in instances:
        for tag in i.tags:
            if tag['Key'] == 'Name':
                instanceName = tag['Value']
                i_list.append('{} {:<35} {:<15} {}'.format(i.instance_id, instanceName, i.instance_type, i.private_ip_address))

    if len(i_list) == 0:
        print('Did not find any ec2 instances.')
        sys.exit()
    questions = [
        inquirer.List(
            'name',
            message='Please select EC2 to login',
            choices=i_list
        ),
    ]
    try:
        answer = inquirer.prompt(questions)
        instance_id = answer['name'].split(' ')[0]

        print('Will login instance:  {}'.format(answer['name']))
        os.system('aws ssm start-session --target {} --region {}'.format(instance_id, CURRENT_REGION))
    except:
        sys.exit(1)

def _ec2_login(keyword):
    if keyword.startswith('i-'):
        instance_id = keyword
    elif keyword.startswith('1'):
        ip = keyword
    else:
        ec2_name = keyword
    if 'ip' in locals() or 'ec2_name' in locals():
        ec2 = boto3.resource('ec2', region_name=CURRENT_REGION)
        if locals().get('ip'):
            filters = [{'Name':'private-ip-address', 'Values': [ip]}]
        if locals().get('ec2_name'):
            filters = [{'Name':'tag:Name', 'Values': [ec2_name]}]
        instances = ec2.instances.filter(Filters=filters)
        for i in instances:
            instance_id = i.instance_id
            break
    os.system('aws ssm start-session --target {} --region {}'.format(instance_id, CURRENT_REGION))

def _sm_search(keyword):
    client = boto3.client('secretsmanager', region_name=CURRENT_REGION)
    ret = client.list_secrets(MaxResults=100)
    _ret_list = ret['SecretList']
    _next = ret.get('NextToken')
    while _next:
        ret_tmp = client.list_secrets(MaxResults=100, NextToken=_next)
        _ret_list.extend(ret_tmp['SecretList'])
        _next = ret_tmp.get('NextToken')
    ret_list = []
    for i in _ret_list:
        if i['Name'].find(keyword) != -1:
            ret_list.append(i['Name'])

    if len(ret_list) == 0:
        print('Did not find any secrets manager.')
        sys.exit()
    questions = [
        inquirer.List(
            'name',
            message='Please select secrets manager',
            choices=ret_list
        ),
    ]
    answer = inquirer.prompt(questions)
    ret = client.get_secret_value(SecretId=answer['name'])
    print(ret['SecretString'])

def _sm_get(secret):
    client = boto3.client('secretsmanager', region_name=CURRENT_REGION)
    try:
        ret = client.get_secret_value(SecretId=secret)
        print(ret['SecretString'])
    except:
        print('Get secrets error.')
        sys.exit(1)

def _sm_create():
    client = boto3.client('secretsmanager', region_name=CURRENT_REGION)
    sm_name = input('Please enter the secrets manager:\n')
    sm_value = input('Please enter the sm value:\n')
    try:
        jsonify_data = json.loads(sm_value)
    except:
        print('The data format is not json, update failed')
        sys.exit()

    ret = client.create_secret(Name=sm_name, SecretString=json.dumps(jsonify_data))
    print(ret)

def _sm_update(keyword):
    client = boto3.client('secretsmanager', region_name=CURRENT_REGION)
    ret = client.get_secret_value(SecretId=keyword)
    print('Current value is:\n{}'.format(ret['SecretString']))
    data = input('Please enter the new value:\n')
    try:
        jsonify_data = json.loads(data)
    except:
        print('The data format is not json, update failed')
        sys.exit()

    ret = client.update_secret(SecretId=keyword, SecretString=json.dumps(jsonify_data))
    print(ret)

def _sm_delete(keyword):
    client = boto3.client('secretsmanager', region_name=CURRENT_REGION)
    data = input('Please confirm this deletion[y/n]: ')
    if data.strip().lower() == 'y':
        print('The sm: {} will be deleted'.format(keyword))
        ret = client.delete_secret(
            SecretId=keyword,
            #RecoveryWindowInDays=7,
            ForceDeleteWithoutRecovery=True
        )
        print(ret)
    else:
        print('The sm: {} will not be deleted'.format(keyword))
        sys.exit()

def ssm_search(keyword, option='Contains'):
    client = boto3.client('ssm', region_name=CURRENT_REGION)
    _filter = [
        {
            'Key': 'Name',
            'Option': option,
            'Values': [ keyword ]
        }
    ]
    ret = client.describe_parameters(ParameterFilters=_filter, MaxResults=50)
    _ret_list = ret['Parameters']
    _next = ret.get('NextToken')
    while _next:
        ret_tmp = client.describe_parameters(ParameterFilters=_filter, MaxResults=50, NextToken=_next)
        _ret_list.extend(ret_tmp['Parameters'])
        _next = ret_tmp.get('NextToken')

    ret_list = [ i['Name'] for i in _ret_list ]
    return ret_list

def _ssm_search(keyword):
    ret_list = ssm_search(keyword)
    if len(ret_list) == 0:
        print('Did not find any parameters.')
        sys.exit()
    questions = [
        inquirer.List(
            'name',
            message='Please select parameter',
            choices=ret_list
        ),
    ]
    answer = inquirer.prompt(questions)
    client = boto3.client('ssm', region_name=CURRENT_REGION)
    ret = client.get_parameter(Name=answer['name'], WithDecryption=True)
    print(ret['Parameter']['Value'])

def _ssm_get(keyword):
    client = boto3.client('ssm', region_name=CURRENT_REGION)
    try:
        ret = client.get_parameter(Name=keyword, WithDecryption=True)
        print(ret['Parameter']['Value'])
    except:
        print('Get parameter error.')
        sys.exit(1)

def _ssm_delete(keyword):
    client = boto3.client('ssm', region_name=CURRENT_REGION)
    data = input('Please confirm this deletion[y/n]: ')
    if data.strip().lower() == 'y':
        if not keyword.endswith('/'):
            print('The ssm: {} will be deleted'.format(keyword))
            try:
                ret = client.delete_parameter(Name=keyword)
                print(ret)
            except client.exceptions.ParameterNotFound:
                print('Pamameter not found.')
        else:
            print('The ssm startswith {} will be deleted'.format(keyword))
            ret_list = ssm_search(keyword, 'BeginsWith')
            for r in ret_list:
                print(r)
                try:
                    ret = client.delete_parameter(Name=r)
                    print(ret)
                except client.exceptions.ParameterNotFound:
                    print('Pamameter not found.')
    else:
        print('Cancelled.')
        sys.exit()


def _ecr_account_check():
    if not AWS_ECR_ACCOUNT or not AWS_ECR_REGION:
        print('ECR account or ECR region is not defined, please define them in local environment')
        print('''
example:
export AWS_ECR_ACCOUNT=xxxxx
export AWS_ECR_REGION=us-west-2
''')
        return False
    return True

def _image_list(service):
    _ecr_account_check()
    client = boto3.client('ecr', region_name=AWS_ECR_REGION)
    try:
        ret = client.list_images(
            registryId=AWS_ECR_ACCOUNT,
            repositoryName=service,
            filter={
                'tagStatus': 'TAGGED'
            }
        )
    except:
        print('Service {} ECR is not exist or you do not have permission to list ECR.'.format(service))
        sys.exit(1)

    _ret_list = ret['imageIds']
    _next = ret.get('NextToken')
    while _next:
        ret_tmp = client.list_images(MaxResults=100, NextToken=_next)
        _ret_list.extend(ret_tmp['imageTag'])
        _next = ret_tmp.get('NextToken')
    ret_list = []
    for i in _ret_list:
        ret_list.append(i['imageTag'])
    for j in ret_list:
        print('{}.dkr.ecr.{}.amazonaws.com/{}:{}'.format(AWS_ECR_ACCOUNT, AWS_ECR_REGION, service, j))

def _image_pull(image):
    _ecr_account_check()
    subprocess.run('aws ecr get-login-password --region {1} | docker login --username AWS \
        --password-stdin {0}.dkr.ecr.{1}.amazonaws.com'.format(AWS_ECR_ACCOUNT, AWS_ECR_REGION),
        shell=True,
        stderr=sys.stderr,
        stdout=sys.stdout,
        check=True)
    subprocess.run(['docker', 'pull', image],
        stderr=sys.stderr,
        stdout=sys.stdout,
        check=True)

def _image_cve(service, tag):
    _ecr_account_check()
    subprocess.run('aws ecr describe-image-scan-findings --region {1} --registry-id {0} --repository-name {2} \
        --image-id imageTag={3} | jq ".imageScanFindings.findings[] | \\"\(.severity) \(.name) \(.description)\\""'.format(AWS_ECR_ACCOUNT, AWS_ECR_REGION, service, tag),
        shell=True,
        stderr=sys.stderr,
        stdout=sys.stdout,
        check=True)

def _image_run(service, tag):
    _ecr_account_check()
    port_cmd = ''
    if len(tag) == 2:
        try:
            if isinstance(int(tag[1]), int) and int(tag[1]) >= 1000:
                port_cmd = '-p {0}:{0}'.format(tag[1])
        except:
            print('service port is invalid.')
            sys.exit(1)
        
    run_cmd = 'docker run --rm -d {4} -v ~/.aws:/root/.aws --env-file ~/.{0}_env \
{1}.dkr.ecr.{2}.amazonaws.com/{0}:{3}'.format(service, AWS_ECR_ACCOUNT, AWS_ECR_REGION, tag[0], port_cmd)
    try:
        subprocess.run(run_cmd,
            shell=True,
            stderr=sys.stderr,
            stdout=sys.stdout,
            check=True)
    except subprocess.CalledProcessError as e:
        print(e)

if __name__ == "__main__":
    main()
