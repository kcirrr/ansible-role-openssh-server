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
    assert f.contains("KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256")
    assert f.contains("Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr")
    assert f.contains("MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com")
    assert f.contains("PermitRootLogin no")
    assert f.contains("UseDNS no")
    assert f.contains("PasswordAuthentication no")
    assert f.user == "root"
    assert f.group == "root"
    assert f.mode == 0o644
