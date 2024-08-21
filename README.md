# AWS command wrapper script

## Setup  ##

- Install awscli version 2.0+

https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html

- Install the Session Manager plugin for the AWS CLI

https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html

- add this line to `~/.bashrc`
    
  eval "$(register-python-argcomplete asso)"
    
Then you use asso to login aws, switch AWS accounts/roles, login ec2 instance, search or update secretsmanager or ssm
