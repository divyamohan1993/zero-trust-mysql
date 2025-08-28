resource "google_compute_network" "net" {
  name = var.network_name
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "subnet" {
  name          = "${var.network_name}-subnet"
  ip_cidr_range = var.subnet_cidr
  region        = var.region
  network       = google_compute_network.net.id
  private_ip_google_access = true
}

resource "google_compute_firewall" "ssh" {
  name    = "${var.network_name}-ssh"
  network = google_compute_network.net.name
  allow { protocol = "tcp" ports = ["22"] }
  source_ranges = var.allow_cidrs
}

resource "google_compute_firewall" "mysql" {
  name    = "${var.network_name}-mysql"
  network = google_compute_network.net.name
  allow { protocol = "tcp" ports = ["3306"] }
  source_ranges = var.allow_cidrs
}

resource "google_compute_instance" "vm" {
  name         = var.instance_name
  machine_type = var.machine_type
  zone         = var.zone

  boot_disk {
    initialize_params {
      image = var.image
      size  = 50
      type  = "pd-ssd"
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.subnet.name
    access_config {}
  }

  service_account {
    email  = var.service_account_email
    scopes = ["https://www.googleapis.com/auth/cloud-platform"]
  }

  shielded_instance_config {
    enable_secure_boot = true
    enable_vtpm        = true
    enable_integrity_monitoring = true
  }

  metadata = {
    enable-oslogin = "TRUE"
  }
}