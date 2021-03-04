import base64
import boto3
from jinja2 import Environment, FileSystemLoader
import json
import os
import re
import subprocess
from time import sleep

def run_command(command):
    process = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True, env=os.environ)
    while True:
        output = process.stdout.readline()
        if len(output) == 0 and process.poll() is not None:
            break
        if output:
            print(output.strip())
    rc = process.poll()
    return rc


def execute_terraform(aws_access_key, aws_secret_key, terraform_directory, terraform_action):
    """
    Function to build and execute Terraform to deploy necessary IAM policies to your account
    :param aws_access_key: Your AWS Access Key
    :param aws_secret_key: Your AWS Secret Access Key
    :return: None
    """
    if terraform_action.lower in ('apply', 'destroy'):
        run_command(f"terraform -chdir={terraform_directory} init")
        command = f"terraform -chdir={terraform_directory} {terraform_action} -var 'access_key={aws_access_key}' -var " \
                  f"'secret_key={aws_secret_key}' -auto-approve"
        print(command)
        run_command(command)
    elif terraform_action.lower() == 'refresh':
        run_command(f"terraform -chdir={terraform_directory} init")
        command = f"terraform -chdir={terraform_directory} {terraform_action} -var 'access_key={aws_access_key}' -var " \
                  f"'secret_key={aws_secret_key}'"
        print(command)
        run_command(command)



def return_terraform_output(terraform_directory):
    f = open(f"{terraform_directory}/terraform.tfstate")
    data = json.load(f)
    # print(data['outputs']['letsencrypt_access_key']['value'])
    # print(data['outputs']['letsencrypt_secret_key']['value'])
    return {"r53_access_key": data['outputs']['letsencrypt_access_key']['value'],
            "r53_secret_key": data['outputs']['letsencrypt_secret_key']['value'],
            "cert-manager-policy-arn": data['outputs']['cert_manager_policy_arn']['value'],
            "aws-lb-controller-policy-arn": data['outputs']['aws_lb_controller_policy_arn']['value'],
            "external-dns-policy-arn": data['outputs']['external_dns_policy_arn']['value']
            }


def build_eks_config_template(cluster_name, terraform_output):
    print("Creating EKS Config Template")
    file_loader = FileSystemLoader('./templates')
    env = Environment(loader=file_loader)
    base_dir = "./infrastructure/EKS"
    # set template variables
    cert_mgr_arn = terraform_output['cert-manager-policy-arn']
    aws_lb_arn = terraform_output['aws-lb-controller-policy-arn']
    ext_dns_arn = terraform_output['external-dns-policy-arn']
    template = env.get_template('./sso-cluster-conf.yaml.hbs')
    output = template.render(cluster_name=cluster_name, external_dns_policy_arn=ext_dns_arn,
                             cert_manager_policy_arn=cert_mgr_arn, aws_lb_controller_policy_arn=aws_lb_arn)
    with open(f'{base_dir}/sso-cluster-conf.yaml', 'w') as eks_template:
        eks_template.write(output)


def build_letsencrypt_issuer_template(terraform_output):
    print("Executing creation of letsencrypt clusterissuer template for cert manager")
    file_loader = FileSystemLoader('./templates')
    env = Environment(loader=file_loader)
    base_dir = "./kubernetes/namespaces/cert-manager"
    template = env.get_template("./le-issuer.yaml.hbs")
    # set access key
    r53_access_key = terraform_output['r53_access_key']
    # render template
    output = template.render(dns_zone_name=dns_zone_name, r53_access_key=r53_access_key)
    with open(f"{base_dir}/le-issuer.yaml", 'w') as le_template:
        le_template.write(output)


def build_letsencrypt_secret_template(terraform_output):
    print("Executing creation of letsencrypt aws secret key template")
    file_loader = FileSystemLoader('./templates')
    env = Environment(loader=file_loader)
    base_dir = "./kubernetes/namespaces/cert-manager"
    template = env.get_template("./aws-keys.yaml.hbs")
    # set secret key
    r53_secret_key = terraform_output['r53_secret_key']
    # render template
    output = template.render(r53_secret_key=r53_secret_key)
    with open(f"{base_dir}/aws-keys.yaml", 'w') as aws_secret:
        aws_secret.write(output)


def build_aws_lb_template(cluster_name):
    """
    Update and build aws_lb controller yaml template
    :param cluster_name: desired name for cluster that eksctl will create
    :return: none
    """
    print("Executing creation of aws-lb-controller template")
    file_loader = FileSystemLoader('./templates')
    env = Environment(loader=file_loader)
    base_dir = "./kubernetes/namespaces/kube-system"
    template = env.get_template("./aws-lb-controller.yaml.hbs")
    # render template
    output = template.render(cluster_name=cluster_name)
    with open(f"{base_dir}/aws-lb-controller.yaml", 'w') as aws_lb:
        aws_lb.write(output)


def build_keycloak_certificate(keycloak_hostname):
    """
    Build template to request certificate from lets encrypt kubernetes cluster issuer
    :param keycloak_hostname: desired hostname for Route53 to create for Keycloak
    :return: None
    """
    print("Creating TLS Certificate for Keycloak")
    file_loader = FileSystemLoader('./templates')
    env = Environment(loader=file_loader)
    base_dir = f"{kube_basedir}/keycloak"
    template = env.get_template('./keycloak-cert.yaml.hbs')
    # render template
    output = template.render(keycloak_hostname=keycloak_hostname)
    with open(f"{base_dir}/keycloak-cert.yaml", 'w') as cert:
        cert.write(output)


def upload_keycloak_certificate(keycloak_hostname, upload_cert):
    print('Outputting certificate data to temporary file')
    # Add awful logic that's likely to fail to handle waiting for cert creation
    client = boto3.client('acm')
    if upload_cert.lower() == "false":
        response = client.list_certificates()
        return response
    else:
        while True:
            try:
                file = run_command(f"kubectl get secret {keycloak_hostname} -n keycloak -o json > /tmp/cert.json")
                print(file)
                if file == "1":
                    raise Exception
                f = open("/tmp/cert.json")
                break
            except FileNotFoundError:
                print("Certificate still awaiting verification\nSleeping for 15 seconds")
                sleep(15)
        data = json.load(f)
        cert = base64.standard_b64decode(data['data']['tls.crt'])
        # Separate Chained Certificates and upload to ACM
        regex = re.search(r'(?!<=-----BEGIN CERTIFICATE-----).*?(?<=-----END CERTIFICATE-----)'.encode(), cert, flags=re.DOTALL)
        priv_key = base64.standard_b64decode(data['data']['tls.key'])
        print('Trying Upload to ACM')
        response = client.import_certificate(
            Certificate=regex.group(),
            PrivateKey=priv_key,
            CertificateChain=cert
        )
        cert_arn = response['CertificateArn']
        if cert_arn is not None:
            print("Upload Successful")
        return cert_arn


def helm_deploy_keycloak(keycloak_user, keycloak_pass, keycloak_cert_arn, keycloak_hostname):
    print("Building Helm chart for keycloak deployment")
    file_loader = FileSystemLoader('./templates')
    env = Environment(loader=file_loader)
    base_dir = f"{kube_basedir}/keycloak/helm"
    template = env.get_template('./keycloak-values.yaml.hbs')
    # render template
    output = template.render(keycloak_admin_username=keycloak_user, keycloak_admin_password=keycloak_pass,
                             keycloak_certificate_arn=keycloak_cert_arn, keycloak_hostname=keycloak_hostname)
    with open(f'{base_dir}/keycloak-values.yaml', 'w') as chart:
        chart.write(output)


def build_test_deployment_template(test_host_dns1, test_host_dns2):
    print("Building test deployment yaml")
    file_loader = FileSystemLoader('./templates')
    env = Environment(loader=file_loader)
    base_dir = f"{kube_basedir}/kong"
    template = env.get_template('./test.yaml.hbs')
    # render template
    output = template.render(helloworld_hostname1=test_host_dns1, helloworld_hostname2=test_host_dns2)
    with open(f"{base_dir}/test.yaml", "w") as test:
        test.write(output)


def build_kong_deployment_template(kong_image):
    print("Building Kong deployment yaml")
    file_loader = FileSystemLoader('./templates')
    env = Environment(loader=file_loader)
    base_dir = f"{kube_basedir}/kong"
    template = env.get_template('./kong.yaml.hbs')
    # render template
    output = template.render(kong_image=kong_image)
    with open(f"{base_dir}/kong.yaml", "w") as kong:
        kong.write(output)


if __name__ == '__main__':
    # Global Variables
    aws_access_key = os.getenv('AWS_ACCESS_KEY_ID')
    aws_secret_key = os.getenv('AWS_SECRET_ACCESS_KEY')
    terraform_action = os.getenv('TERRAFORM_COMMAND')
    eks_action = os.getenv('EKS_ACTION')
    create_keycloak = os.getenv('CREATE_KEYCLOAK')
    upload_cert = os.getenv('UPLOAD_CERT')
    helm_action = os.getenv('HELM_ACTION')
    test_host_dns1 = os.getenv('TEST_HOST_DNS1')
    test_host_dns2 = os.getenv('TEST_HOST_DNS2')
    kong_image = os.getenv('KONG_IMAGE')
    # Define which action to take before exit
    cleanup_action = os.getenv('CLEANUP_ACTION')
    cluster_name = os.getenv('CLUSTER_NAME')
    dns_zone_name = os.getenv('DNS_HOSTED_ZONE_NAME')
    # Keycloak Vars
    keycloak_hostname = os.getenv('KEYCLOAK_HOSTNAME')
    keycloak_user = os.getenv('KEYCLOAK_USER')
    keycloak_pass = os.getenv('KEYCLOAK_PW')
    # Set base dir for kubectl apply
    kube_basedir = "/app/kubernetes/namespaces"
    # Initialize and Execute Terraform
    terraform_directory = "./infrastructure/iam"


    execute_terraform(aws_access_key, aws_secret_key, terraform_directory, terraform_action)

    # Return AWS Keys and Policy ARNs for Created Route53 User and Policies
    terraform_output = return_terraform_output(terraform_directory)
    build_eks_config_template(cluster_name=cluster_name, terraform_output=terraform_output)

    # Create Cluster with eksctl
    print(eks_action)
    if eks_action.lower() == "create":
        run_command(f"eksctl create cluster -f ./infrastructure/EKS/sso-cluster-conf.yaml")
    elif eks_action.lower() == "iam":
        run_command(f"eksctl create iamserviceaccount -f ./infrastructure/EKS/sso-cluster-conf.yaml "
                    f"--override-existing-serviceaccounts --approve")
    elif eks_action.lower() == "destroy":
        run_command(f"eksctl delete cluster -f ./infrastructure/EKS/sso-cluster-conf.yaml")
    # Get Cluster Info for Authentication
    run_command(f"eksctl utils write-kubeconfig {cluster_name}")
    # Build Lets Encrypt Templates
    build_letsencrypt_issuer_template(terraform_output)
    build_letsencrypt_secret_template(terraform_output)
    # Build AWS-lb-controller Template
    build_aws_lb_template(cluster_name)
    # Build Keycloak Certificate request template
    build_keycloak_certificate(keycloak_hostname)
    # Execute apply for cert-manager
    print("Executing kubectl apply for cert-manager")
    run_command(f"kubectl apply -f /app/kubernetes/namespaces/cert-manager/cert-manager.yaml")
    # Execute apply for external-dns
    print("Executing kubectl apply for external-dns")
    run_command(f"kubectl apply -f {kube_basedir}/external-dns/")
    # Create Keycloak Namespace
    print("Creating Keycloak Namespace")
    run_command(f"kubectl apply -f {kube_basedir}/keycloak/keycloak-namespace.yaml")
    # Create Cluster Certificate Issuer
    print(f"Creating LetsEncrypt Cluster Issuer")
    print("Waiting for cert-manager resources to become available\nSleeping for 60")
    sleep(60)
    run_command(f"kubectl apply -f {kube_basedir}/cert-manager/aws-keys.yaml")
    run_command(f"kubectl apply -f {kube_basedir}/cert-manager/le-issuer.yaml")
    print("Deploying AWS LB Controller")
    run_command(f"kubectl apply -f {kube_basedir}/kube-system/aws-lb-controller.yaml")
    # Request Certificate from now deployed Lets Encrypt Issuer
    print(f"Requesting certificate for {keycloak_hostname} from LetsEncrypt")
    run_command(f"kubectl apply -f {kube_basedir}/keycloak/keycloak-cert.yaml")
    # upload certificate to AWS ACM
    keycloak_cert_arn = upload_keycloak_certificate(keycloak_hostname, upload_cert)
    print(keycloak_cert_arn)
    # Build Keycloak Helm Chart
    helm_deploy_keycloak(keycloak_user=keycloak_user, keycloak_cert_arn=keycloak_cert_arn, keycloak_pass=keycloak_pass,
                         keycloak_hostname=keycloak_hostname)
    print("Keycloak Helm Chart created")
    # Deploy Keycloak via Helm
    print("Adding Keycloak Helm repository")
    run_command("helm repo add codecentric https://codecentric.github.io/helm-charts")
    print("Deploying Keycloak")
    if create_keycloak.lower() == "true" and helm_action.lower() == 'install':
        run_command(f"helm install keycloak -n keycloak codecentric/keycloak -f "
                    f"{kube_basedir}/keycloak/helm/keycloak-values.yaml")
    elif create_keycloak.lower() == "true" and helm_action.lower() == 'upgrade':
        run_command(f"helm upgrade keycloak -n keycloak codecentric/keycloak -f "
                    f"{kube_basedir}/keycloak/helm/keycloak-values.yaml")
    print("Building Kong Templates")
    build_kong_deployment_template(kong_image)
    build_test_deployment_template(test_host_dns1, test_host_dns2)
    print("Deploying Kong controller")
    print("Waiting for controller to come up\nSleep 30")
    run_command(f"kubectl apply -f {kube_basedir}/kong/kong-crd.yaml")
    run_command(f"kubectl apply -f {kube_basedir}/kong/kong.yaml")
    sleep(30)
    print("Deploying cors-plugin")
    run_command(f"kubectl apply -f {kube_basedir}/kong/cors-plugin.yaml")


# Execute Terraform #1 DONE
# Jsonload Terraform Keys - DONE
# json parse terraform keys - DONE
# Create cluster with EKSCTL #2 DONE
# Get EKSCTL Auth information #3 DONE
# Load Templates
# Execute
### cert-manager DONE templates
### external-dns
### keycloak certificate request & upload
### application-lb DONE templates
### Template Keycloak Helm for ACM upload
### Keycloak Helm

### Separate ###
# - Keycloak Manual Setup
# - Kong Deployment
# - Helloworld app deployment

# Variables #
# Kong:
# - helloworld-hostname1 -> test.yaml.hbs (user provided)
# - helloworld-hostname2 -> test.yaml.hbs (user provided)
# - keycloak_client_id -> oidc-plugin.yaml.hbs (user provided)
# - keycloak_client_secret -> oidc-plugin.yaml.hbs (user provided)
# - keycloak_oidc_discovery_endpoint -> oidc-plugin.yaml.hbs (user provided)
# - keycloak_realm -> oidc-plugin.yaml.hbs (user provided)
# - kong_image -> kong.yaml.hbs ( user provided)


