output "letsencrypt_secret_key" {
  description = "letsencrypt user secret key"
  value = aws_iam_access_key.letsencrypt.secret
}

output "letsencrypt_access_key" {
  description = "letsencrypt user access key"
  value = aws_iam_access_key.letsencrypt.id
}

output "external_dns_policy_arn" {
  description = "AWS Policy ARN for the created external-dns IAM policy"
  value = aws_iam_policy.external_dns.arn
}

output "cert_manager_policy_arn" {
  description = "AWS Policy ARN for the created cert-manager IAM policy"
  value = aws_iam_policy.cert-manager.arn
}

output "aws_lb_controller_policy_arn" {
  description = "AWS Policy ARN for the created aws-lb-controller IAM policy"
  value = aws_iam_policy.awsloadbalancer.arn
}