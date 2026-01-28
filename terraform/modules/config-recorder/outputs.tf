# Outputs for Config Recorder Module

output "recorder_id" {
  description = "The ID of the Config recorder"
  value       = aws_config_configuration_recorder.main.id
}

output "recorder_name" {
  description = "The name of the Config recorder"
  value       = aws_config_configuration_recorder.main.name
}

output "delivery_channel_id" {
  description = "The ID of the delivery channel"
  value       = aws_config_delivery_channel.main.id
}

output "region" {
  description = "The region where this recorder is deployed"
  value       = data.aws_region.current.name
}

output "account_id" {
  description = "The account ID where this recorder is deployed"
  value       = data.aws_caller_identity.current.account_id
}
