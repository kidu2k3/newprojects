# BIND9 Setup for .alt TLD (Authoritative Internal DNS)

## Purpose
Configure BIND9 to serve as the authoritative DNS server for .alt domains, ensuring only the app owner can manage the root zone.

## Steps

1. **Install BIND9**
   ```bash
   sudo apt-get update
   sudo apt-get install bind9 bind9utils
   ```

2. **Create Zone File for .alt**
   Example: `/etc/bind/zones/db.alt`
   ```
   $TTL 1H
   @   IN  SOA ns1.alt. admin.alt. (
           2025062301 ; Serial
           1H         ; Refresh
           15M        ; Retry
           1W         ; Expire
           1H )       ; Minimum
       IN  NS  ns1.alt.
   ns1 IN  A   10.0.0.1
   example IN  A   10.0.0.2
   ```

3. **Update named.conf.local**
   ```
   zone "alt" {
       type master;
       file "/etc/bind/zones/db.alt";
       allow-update { none; };
   };
   ```

4. **Restrict Zone File Permissions**
   ```bash
   sudo chown root:bind /etc/bind/zones/db.alt
   sudo chmod 640 /etc/bind/zones/db.alt
   ```

5. **Restrict BIND Management**
   - Only the app owner (root or a specific admin user) should have write access to zone files and BIND configuration.
   - Use `sudo` for all BIND management commands.

6. **Reload BIND9**
   ```bash
   sudo systemctl reload bind9
   ```

## Security Practices

- Limit shell and file access to the app owner/admin.
- Use firewall rules to restrict DNS port (53/UDP) to internal network.
- For dynamic updates, configure TSIG keys and restrict update permissions.
- Monitor logs for unauthorized access attempts.

## Owner-Only Management

- Only the designated owner/admin user should have sudo privileges for BIND9 and zone file management.
- Document and enforce operational procedures for secure TLD management.

---
