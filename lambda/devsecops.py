"""
devsecops.py

This is what our team came up with for offering Unicorn group DevSecOps...
Maybe a semi standard solution would have been better like:
https://aws.amazon.com/answers/devops/aws-cloudformation-validation-pipeline/
or
https://aws.amazon.com/blogs/devops/implementing-devsecops-using-aws-codepipeline/

Another team will *hopefully* close the loop doing dynamic analysis with:
AWS Cloudwatch Events & AWS Config Rules, or things like:
https://github.com/capitalone/cloud-custodian
https://github.com/Netflix/security_monkey

And because DevSecOps is also about broadening the shared responsibility of security,
as well as automation, we have a basic function here for publishing to a Slack channel.

"""
import ruamel.yaml
import json
import base64
from urllib.parse import urljoin
from urllib.parse import urlencode
import urllib.request as urlrequest

#Configure these to Slack for ChatOps
SLACK_CHANNEL = '' #Slack Channel to target
HOOK_URL = '' #Like https://hooks.slack.com/services/T3KsdfVTL/B3dfNJ4V8/HmsgdXdzjW16pAD3CdASQChI

# Helper Function to enable us to put visibility into chat ops. Also outputs to Cloudwatch Logs.
# The Slack channel to send a message to stored in the slackChannel environment variable
def send_slack(message, username="SecurityBot", emoji=":exclamation:"):
    print(message)
    if not HOOK_URL:
        return None
    slack_message = {
        'channel': SLACK_CHANNEL,
        'text': message,
         "username": username
    }
    try:
        opener = urlrequest.build_opener(urlrequest.HTTPHandler())
        payload_json = json.dumps(slack_message)
        data = urlencode({"payload": payload_json})
        req = urlrequest.Request(HOOK_URL)
        response = opener.open(req, data.encode('utf-8')).read()
        return response.decode('utf-8')
    except:
        print("Slack connection failed. Valid webhook?")
        return None

# Define a YAML reader for parsing Cloudformation to handle !Functions like Ref
def general_constructor(loader, tag_suffix, node):
    return node.value
ruamel.yaml.SafeLoader.add_multi_constructor(u'!', general_constructor)

# Define basic security globals
SECURE_PORTS = ["443","22"]
DB_PORTS = ["3306"]
TAGS = ["Name", "Role", "Owner", "CostCenter"]
ACCESS_CONTROL_S3 = ["PublicRead", "PublicReadWrite"]

#Our DevSecOps Logic
def handler(event, context):
    yaml = base64.b64decode(event['b64template'])
    cfn = ruamel.yaml.safe_load(yaml)

    # We return result for scoring. it needs a policyN entry for every rule, with count of violations.
    # Errors is for informational purposes, and not required for scoring
    result = {
        "pass":True,
        "policy0":0,
        "policy1":0,
        "policy2":0,
        "policy3":0,
        "errors":[]
    }

    send_slack("BUILD: Starting DevSecOps static code analysis of CFN template: {}".format(cfn['Description']))

    ########################YOUR CODE GOES UNDER HERE########################
    #Now we loop over resources in the template, looking for policy breaches

    for resource in cfn['Resources']:
        #Test for Security Groups for Unicorn Security policy0
        if cfn['Resources'][resource]["Type"] == """AWS::EC2::SecurityGroup""":
            if "SecurityGroupIngress" in cfn['Resources'][resource]["Properties"]:
                for rule in cfn['Resources'][resource]["Properties"]['SecurityGroupIngress']:

                    send_slack("BUILD: Found SG rule: {}".format(rule))

                    #Test that SG ports are only 22 or 443 if open to /0
                    if "CidrIp" in rule:
                        if (rule["FromPort"] not in SECURE_PORTS or rule["ToPort"] not in SECURE_PORTS) and rule["CidrIp"] == '0.0.0.0/0':
                            result['pass'] = False
                            result['policy0'] += 1 #Add one to our policy fail counter
                            result["errors"].append("policy0: Port {} not allowed for /0".format(rule["FromPort"]))

                        #lets catch ranges (i.e 22-443)
                        if rule["FromPort"] != rule["ToPort"] and rule["CidrIp"] == '0.0.0.0/0':
                            result['pass'] = False
                            result['policy0'] += 1 #Add one to our policy fail counter
                            result["errors"].append("policy0: Port range {}-{} is not allowed for /0".format(rule["FromPort"],rule["ToPort"]))

                        if rule["FromPort"] in DB_PORTS and rule["ToPort"] in DB_PORTS:
                            result['pass'] = False
                            result['policy0'] += 1 #Add one to our policy fail counter
                            result["errors"].append("policy0: Port range {}-{} not allowed for SG using CidrIp".format(rule["FromPort"],rule["ToPort"]))

                        if int(rule["FromPort"]) < 3306 and int(rule["ToPort"]) > 3306:
                            result['pass'] = False
                            result['policy0'] += 1
                            result["errors"].append("policy0: Port Range has DB Port and is using CIDR")

                    if 'SourceSecurityGroupName' in rule:
                        if rule["FromPort"] in DB_PORTS and rule["ToPort"] in DB_PORTS and rule["SourceSecurityGroupName"] != 'WebServerSecurityGroup':
                            result['pass'] = False
                            result['policy0'] += 1 #Add one to our policy fail counter
                            result["errors"].append("policy0: Port range {}-{} not allowed for Groups other than WebServerSecurityGroup".format(rule["FromPort"],rule["ToPort"]))

        if cfn['Resources'][resource]["Type"] == """AWS::S3::Bucket""":
            if "Properties" in cfn['Resources'][resource]:
                if "AccessControl" in cfn['Resources'][resource]["Properties"]:
                    acl = cfn['Resources'][resource]["Properties"]["AccessControl"]

                    if acl in ACCESS_CONTROL_S3:
                        result['pass'] = False
                        result['policy0'] += 1 #Add one to our policy fail counter
                        result["errors"].append("policy0: AccessControl setting {} not allowed for S3 Bucket".format(acl))

        if cfn['Resources'][resource]["Type"] == """AWS::IAM::User""":
            if "Policies" in cfn['Resources'][resource]["Properties"]:
                policies = cfn['Resources'][resource]["Properties"]["Policies"]

                for policy in policies:
                    if "PolicyDocument" in policy:
                        if "Statement" in policy["PolicyDocument"]:
                            statements = policy["PolicyDocument"]["Statement"]

                            for statement in statements:
                                if statement["Effect"] == """Allow""":
                                    if statement["Action"] == """*""":
                                        result['pass'] = False
                                        result['policy1'] += 1 #Add one to our policy fail counter
                                        result["errors"].append("policy1: * Action not allowed in inline policies")

                                    if "iam" in statement["Action"]:
                                        result['pass'] = False
                                        result['policy1'] += 1 #Add one to our policy fail counter
                                        result["errors"].append("policy1: iam Action not allowed in inline policies")

                                    if "organizations" in statement["Action"]:
                                        result['pass'] = False
                                        result['policy1'] += 1 #Add one to our policy fail counter
                                        result["errors"].append("policy1: organisation Action not allowed in inline policies")

            if "ManagedPolicyArns" in cfn['Resources'][resource]["Properties"]:
                for policy in cfn['Resources'][resource]["Properties"]["ManagedPolicyArns"]:
                    if not ("AWSSupportAccess" in policy or "SupportUser" in policy or "CloudWatch" in policy):
                        result['pass'] = False
                        result['policy1'] += 1 #Add one to our policy fail counter
                        result["errors"].append("policy1: Only Support or Cloudwatch managed policies are allowed")

        if cfn['Resources'][resource]["Type"] == """AWS::EC2::Instance""":
            if not "IamInstanceProfile" in cfn['Resources'][resource]:
                result['pass'] = False
                result['policy1'] += 1 #Add one to our policy fail counter
                result["errors"].append("policy1: EC2 instances need to include IamInstanceProfile")

        if cfn['Resources'][resource]["Type"] == """AWS::ElasticLoadBalancing::LoadBalancer""":
            if "Properties" in cfn['Resources'][resource]:
                if not ("AccessLoggingPolicy" in cfn['Resources'][resource]["Properties"]):
                    result['pass'] = False
                    result['policy2'] += 1
                    result["errors"].append("policy2: AccessLogggingPolicy property not found")

                if ("AccessLoggingPolicy" in cfn['Resources'][resource]["Properties"]):
                    #send_slack("deb {}".format(cfn['Resources'][resource]["Properties"]['AccessLoggingPolicy']['Enabled']))
                    if cfn['Resources'][resource]["Properties"]['AccessLoggingPolicy']['Enabled'] != True :
                        result['pass'] = False
                        result['policy2'] += 1
                        result["errors"].append("policy2: AccessLoggingPolicy Set to {} Must be enabled".format(cfn['Resources'][resource]["Properties"]['AccessLoggingPolicy']['Enabled']))

        if cfn['Resources'][resource]["Type"] == """AWS::CloudFront::Distribution""":
            if 'Logging' not in cfn['Resources'][resource]["Properties"]["DistributionConfig"]:
                result['pass'] = False
                result['policy2'] += 1 #Add one to our policy fail counter
                result["errors"].append("Policy2 Subrule1: Logging doesn't exist. CloudFront logs need to be enabled.")

            if 'ViewerProtocolPolicy' in cfn['Resources'][resource]["Properties"]["DistributionConfig"]["DefaultCacheBehavior"]:
                if cfn['Resources'][resource]["Properties"]["DistributionConfig"]["DefaultCacheBehavior"]["ViewerProtocolPolicy"] != "https-only":
                    result['pass'] = False
                    result['policy3'] += 1 #Add one to our policy fail counter
                    result["errors"].append("Policy3 Subrule2: ViewerProtocolPolicy {} is not allowed. https-only.".format(cfn['Resources'][resource]["Properties"]["DistributionConfig"]["DefaultCacheBehavior"]["ViewerProtocolPolicy"]))

    ########################YOUR CODE GOES ABOVE HERE########################
    # Now, how did we do? We need to return accurate statics of any policy failures.
    if not result["pass"]:
        for err in result["errors"]:
            print(err)
            send_slack(err)
        send_slack("Failed DevSecOps static code analysis. Please Fix policy breaches.", username="SecurityBotFAIL", emoji=":exclamation:")
    else:
        send_slack("Passed DevSecOps static code analysis Security Testing", username="SecurityBotPASS", emoji=":white_check_mark:")
    return result
