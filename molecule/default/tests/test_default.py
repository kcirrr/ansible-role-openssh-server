"""Role testing files using testinfra."""


def test_packages(host):
    pkg = host.package("openssh-server")
    assert pkg.is_installed


def test_openssh_server_running_and_enabled(host):
    s = host.service("ssh")
    assert s.is_running
    assert s.is_enabled


def test_openssh_config_file(host):
    f = host.file("/etc/ssh/sshd_config.d/custom.conf")
    assert f.exists
    assert f.contains("Protocol 2")
    assert f.contains("Port 22")
    assert f.contains("HostKey /etc/ssh/ssh_host_ed25519_key")
    assert f.contains("HostKey /etc/ssh/ssh_host_rsa_key")
    assert f.contains("KexAlgorithms curve25519")
    assert f.contains("Ciphers chacha20-poly1305")
    assert f.contains("MACs hmac-sha2-512-etm")
    assert f.contains("PermitRootLogin no")
    assert f.contains("UseDNS no")
    assert f.contains("PasswordAuthentication no")
    assert f.user == "root"
    assert f.group == "root"
    assert f.mode == 0o644
