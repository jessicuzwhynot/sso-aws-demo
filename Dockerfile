FROM python:3.8-alpine

# pip install requests, json, jinja2
# Install wget, tar, and unzip to
RUN apk update && \
    apk add --no-cache wget tar unzip

# Install Binaries not available through Package Manager
ADD https://amazon-eks.s3.us-west-2.amazonaws.com/1.18.9/2020-11-02/bin/linux/amd64/aws-iam-authenticator /usr/bin/aws-iam-authenticator
ADD https://storage.googleapis.com/kubernetes-release/release/v1.18.9/bin/linux/amd64/kubectl /usr/bin/kubectl
RUN wget https://github.com/weaveworks/eksctl/releases/download/0.39.0/eksctl_Linux_amd64.tar.gz && \
    tar -xzvf eksctl_Linux_amd64.tar.gz && \
    chmod +x eksctl &&\
    mv eksctl /usr/bin/eksctl && \
    rm eksctl_Linux_amd64.tar.gz && \
    wget https://get.helm.sh/helm-v3.5.2-linux-amd64.tar.gz && \
    tar -xzvf helm-v3.5.2-linux-amd64.tar.gz && \
    chmod +x linux-amd64/helm && \
    mv linux-amd64/helm /usr/bin/helm && \
    rm -r linux-amd64/ helm-v3.5.2-linux-amd64.tar.gz && \
    wget https://releases.hashicorp.com/terraform/0.14.7/terraform_0.14.7_linux_amd64.zip && \
    unzip terraform_0.14.7_linux_amd64.zip && \
    chmod +x terraform && \
    rm terraform_0.14.7_linux_amd64.zip && \
    mv terraform /usr/bin/terraform && \
    chmod +x /usr/bin/kubectl && \
#    curl -Lo aws-iam-authenticator https://amazon-eks.s3.us-west-2.amazonaws.com/1.18.9/2020-11-02/bin/linux/amd64/aws-iam-authenticator && \
    chmod +x /usr/bin/aws-iam-authenticator
#    mv aws-iam-authenticator /usr/bin/aws-iam-authenticator




COPY ./app /app
RUN pip install -r /app/requirements.txt
WORKDIR /app

# Remove used APK packages