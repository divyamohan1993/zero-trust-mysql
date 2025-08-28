output "vm_name" { value = google_compute_instance.vm.name }
output "vm_ip"   { value = google_compute_instance.vm.network_interface[0].access_config[0].nat_ip }
output "network" { value = google_compute_network.net.name }