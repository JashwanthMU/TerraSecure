# Intentionally vulnerable GCP resources — used by CI to verify the
# GCP rule engine actually fires. Do not deploy this.

resource "google_compute_firewall" "ssh_open" {
  name    = "allow-ssh-anywhere"
  network = "default"

  direction     = "INGRESS"
  source_ranges = ["0.0.0.0/0"]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

resource "google_storage_bucket" "no_versioning" {
  name                        = "example-bucket"
  location                    = "US"
  uniform_bucket_level_access = false
}

resource "google_project_iam_member" "primitive_owner" {
  project = "example-project"
  role    = "roles/owner"
  member  = "user:example@example.com"
}
