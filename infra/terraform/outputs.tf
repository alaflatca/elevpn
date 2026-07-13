output "elevpn_server_instance_id" {
  description = "Instance ID of elevpn-server"
  value       = aws_instance.elevpn_server.id
}

output "elevpn_client_instance_id" {
  description = "Instance ID of elevpn-client"
  value       = aws_instance.elevpn_client.id
}

output "elevpn_server_public_ip" {
  description = "Public IP of elevpn-server"
  value       = aws_instance.elevpn_server.public_ip
}

output "elevpn_client_public_ip" {
  description = "Public IP of elevpn-client"
  value       = aws_instance.elevpn_client.public_ip
}