
coreo_aws_rule "ec2-inventory-instances" do
  action :define
  service :ec2
  link "https://kb.securestate.vmware.com/aws-all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Instance Inventory"
  description "This rule performs an inventory on all EC2 instances in the target AWS account."
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["instances"]
  audit_objects ["object.reservations.instances.instance_id"]
  operators ["=~"]
  raise_when [//]
  id_map "object.reservations.instances.instance_id"
end

coreo_aws_rule "ec2-inventory-security-groups" do
  action :define
  service :ec2
  link "https://kb.securestate.vmware.com/aws-all-inventory.html"
  include_violations_in_count false
  display_name "EC2 Security Group Inventory"
  description "This rule performs an inventory on all EC2 Security Groups in the target AWS account."
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["security_groups"]
  audit_objects ["object.security_groups.group_name"]
  operators ["=~"]
  raise_when [//]
  id_map "object.security_groups.group_id"
end

coreo_aws_rule "ec2-ip-address-whitelisted" do
  action :define
  service :ec2
  link "https://kb.securestate.vmware.com/aws-ec2-ip-address-whitelisted.html"
  display_name "Security Group contains IP address"
  description "Security Group contains IP address"
  category "Security"
  suggested_action "Review Security Group to ensure that the host ip address added is to allowed access."
  level "Low"
  objectives ["security_groups"]
  audit_objects ["object.security_groups.ip_permissions.ip_ranges.cidr_ip"]
  operators ["=~"]
  raise_when [/\/32/]
  id_map "object.security_groups.group_id"
  meta_rule_query <<~QUERY
  {
    sg as var(func: <%= filter['security_group'] %>) @cascade {
      ip as relates_to @filter(<%= filter['ip_permission'] %>) {
        range as relates_to @filter(<%= filter['ip_range'] %>) {
          start as range_start
          end as range_end
          whitelisted as math(start == end)
        }
      }
    }
    open_sg as query(func: uid(sg)) @cascade {
      <%= default_predicates %>
      group_id
      relates_to @filter(uid(ip)) {
        <%= default_predicates %>
        ip_protocol
        relates_to @filter(uid(range) AND eq(val(whitelisted), true)) {
          <%= default_predicates %>
          cidr_ip
        }
      }
    }
    visualize(func: uid(open_sg)) {
      <%= default_predicates %>
      group_name
      description
      relates_to {
        <%= default_predicates %>
        ip_protocol
        from_port
        to_port
        relates_to @filter(has(ip_range)) {
          <%= default_predicates %>
          cidr_ip
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
                            'security_group' => [],
                            'ip_permission' => [],
                            'ip_range' => ['cidr_ip']
                          })
end

coreo_aws_rule "ec2-ebs-snapshots-encrypted" do
  action :define
  service :ec2
  link "https://kb.securestate.vmware.com/aws-ec2-ebs-snapshots-encrypted.html"
  display_name "EBS Volume Snapshots are not Encrypted"
  description "EBS Snapshots should be encrypted to protect data at rest"
  category "Security"
  suggested_action "Ensure all ebs volume snapshots are encrypted"
  level "Medium"
  meta_nist_171_id "3.8.9"
  objectives ["describe_snapshots"]
  call_modifiers [{owner_ids: [ "static.self" ]}]
  audit_objects ["object.snapshots.encrypted"]
  operators ["=="]
  raise_when [false]
  id_map "object.snapshots.snapshot_id"
  meta_compliance (
    [
      { "name" => "nist-sp800-171", "version" => "r1", "requirement" => "3.8.9" }
    ]
  )
  meta_rule_query <<~QUERY
  {
    encryption_unknown as var(func: <%= filter['snapshot'] %>) @filter(NOT has(encrypted)) { }
    encryption_known as var(func: <%= filter['snapshot'] %>) @filter(has(encrypted)) {
      is_encrypted as encrypted
    }
    unencrypted as var(func: uid(encryption_known)) @filter(eq(val(is_encrypted), "false")) { }
    not_encrypted as query(func: uid(encryption_unknown, unencrypted)) {
      <%= default_predicates %>
      snapshot_id
    }
    visualize(func: uid(not_encrypted)){
      <%= default_predicates %>
      relates_to{
        <%= default_predicates %>
        owner 
      }
    }
  }
  QUERY
  meta_rule_node_triggers ({'snapshot' => []})
end

coreo_aws_rule "ec2-unrestricted-traffic" do
  action :define
  service :ec2
  link "https://kb.securestate.vmware.com/aws-ec2-unrestricted-traffic.html"
  display_name "Security group allows unrestricted traffic"
  description "All IP addresses are allowed to access resources in a specific security group."
  category "Security"
  suggested_action "Restrict access to the minimum specific set of IP address or ports necessary."
  level "Low"
  meta_nist_171_id "3.4.7, 3.4.8"
  objectives ["security_groups"]
  audit_objects ["object.security_groups.ip_permissions.ip_ranges.cidr_ip"]
  operators ["=="]
  raise_when ["0.0.0.0/0"]
  id_map "object.security_groups.group_id"
  # TODO: Resolve for IPv6
  meta_compliance (
    [
      { "name" => "nist-sp800-171", "version" => "r1", "requirement" => "3.4.7" },
      { "name" => "nist-sp800-171", "version" => "r1", "requirement" => "3.4.8" }
    ]
  )
  meta_rule_query <<~QUERY
  {
    sg as var(func: <%= filter['security_group'] %>) @cascade {
      ip as relates_to @filter(<%= filter['ip_permission'] %>) {
        range as relates_to @filter(<%= filter['ip_range'] %>) {
          start as range_start
          end as range_end
          open as math(end - start == <%= 2**32 - 1 %>)
        }
      }
    }
    open_sg as query(func: uid(sg)) @cascade {
      <%= default_predicates %>
      group_id
      relates_to @filter(uid(ip)) {
        <%= default_predicates %>
        ip_protocol
        relates_to @filter(uid(range) AND eq(val(open), true)) {
          <%= default_predicates %>
          cidr_ip
        }
      }
    }
    visualize(func: uid(open_sg)) {
      <%= default_predicates %>
      group_name
      description
      relates_to {
        <%= default_predicates %>
        ip_protocol
        from_port
        to_port
        relates_to @filter(has(ip_range)) {
          <%= default_predicates %>
          cidr_ip
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
                            'security_group' => [],
                            'ip_permission' => [],
                            'ip_range' => ['cidr_ip']
                          })
end

coreo_aws_rule "ec2-all-ports-all-protocols" do
  action :define
  service :ec2
  link "https://kb.securestate.vmware.com/aws-ec2-unrestricted-traffic.html"
  display_name "Security group allows traffic on all ports and all protocols"
  description "IP address(es) are allowed to access resources in a specific security group through any port and any protocol."
  category "Security"
  suggested_action "Restrict access to the minimum specific set of ports and protocols necessary."
  level "Low"
  meta_nist_171_id "3.4.7, 3.4.8"
  objectives ["security_groups"]
  audit_objects ["object.security_groups.ip_permissions.ip_protocol"]
  operators ["=="]
  raise_when ["-1"]
  id_map "object.security_groups.group_id"
  meta_compliance (
    [
      { "name" => "nist-sp800-171", "version" => "r1", "requirement" => "3.4.7" },
      { "name" => "nist-sp800-171", "version" => "r1", "requirement" => "3.4.8" }
    ]
  )
  meta_rule_query <<~QUERY
  {
    sg as var(func: <%= filter['security_group'] %>) @cascade {
      ip as relates_to @filter(<%= filter['ip_permission'] %>) {
        protocol as ip_protocol
      }
    }
    open_sg as query(func: uid(sg)) @cascade {
      <%= default_predicates %>
      group_id
      relates_to @filter(uid(ip) AND eq(val(protocol), "all")) {
        <%= default_predicates %>
        ip_protocol
      }
    }
    visualize(func: uid(open_sg)) {
      <%= default_predicates %>
      group_name
      description
      relates_to {
        <%= default_predicates %>
        ip_protocol
        from_port
        to_port
        relates_to @filter(has(ip_range)) {
          <%= default_predicates %>
          cidr_ip
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers ({
                             'security_group' => [],
                             'ip_permission' => ['ip_protocol']
                           })
end

coreo_aws_rule "ec2-TCP-1521-0.0.0.0-0" do
  action :define
  service :ec2
  link "https://kb.securestate.vmware.com/aws-ec2-tcpportopen.html"
  display_name "TCP port is open - 1521"
  description "Important TCP port is open and/or open to the world."
  category "Security"
  suggested_action "Only open those ports that must be open for your service to operate. Consider deleting or modifying the affected security group."
  level "Low"
  meta_nist_171_id "3.4.7, 3.4.8, 3.13.6"
  objectives ["","","security_groups"]
  audit_objects ["object.security_groups.ip_permissions.ip_protocol", "object.security_groups.ip_permissions.from_port", "object.security_groups.ip_permissions.ip_ranges.cidr_ip"]
  operators ["==","==","=="]
  raise_when ["tcp", 1521, "0.0.0.0/0"]
  id_map "object.security_groups.group_id"
  # TODO resolve for IPv6
  meta_compliance (
    [
      { "name" => "nist-sp800-171", "version" => "r1", "requirement" => "3.4.7" },
      { "name" => "nist-sp800-171", "version" => "r1", "requirement" => "3.4.8" },
      { "name" => "nist-sp800-171", "version" => "r1", "requirement" => "3.13.6" }
    ]
  )
  meta_rule_query <<~QUERY
  {
    sg as var(func: <%= filter['security_group'] %>) @cascade {
      ip as relates_to @filter(<%= filter['ip_permission'] %>) {
        protocol as ip_protocol
        port as from_port
        range as relates_to @filter(<%= filter['ip_range'] %>) {
          start as range_start
          end as range_end
          open as math(end - start == <%= 2**32 - 1 %>)
        }
      }
    }
    open_sg as query(func: uid(sg)) @cascade {
      <%= default_predicates %>
      group_id
      relates_to @filter(uid(ip) AND eq(val(protocol), "tcp") AND eq(val(port), 1521)) {
        <%= default_predicates %>
        ip_protocol
        from_port
        relates_to @filter(uid(range) AND eq(val(open), true)) {
          <%= default_predicates %>
          cidr_ip
        }
      }
    }
    visualize(func: uid(open_sg)) {
      <%= default_predicates %>
      group_name
      description
      relates_to {
        <%= default_predicates %>
        ip_protocol
        from_port
        to_port
        relates_to @filter(has(ip_range)) {
          <%= default_predicates %>
          cidr_ip
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
                            'security_group' => [],
                            'ip_permission' => ['ip_protocol', 'from_port'],
                            'ip_range' => ['cidr_ip']
                          })
end

coreo_aws_rule "ec2-TCP-3306-0.0.0.0-0" do
  action :define
  service :ec2
  link "https://kb.securestate.vmware.com/aws-ec2-tcpportopen.html"
  display_name "TCP port is open - 3306"
  description "Important TCP port is open and/or open to the world."
  category "Security"
  suggested_action "Only open those ports that must be open for your service to operate. Consider deleting or modifying the affected security group."
  level "Low"
  meta_nist_171_id "3.4.7, 3.4.8, 3.13.6"
  objectives ["","","security_groups"]
  audit_objects ["object.security_groups.ip_permissions.ip_protocol", "object.security_groups.ip_permissions.from_port", "object.security_groups.ip_permissions.ip_ranges.cidr_ip"]
  operators ["==","==","=="]
  raise_when ["tcp", 3306, "0.0.0.0/0"]
  id_map "object.security_groups.group_id"
  # TODO resolve for IPv6
  meta_compliance (
    [
      { "name" => "nist-sp800-171", "version" => "r1", "requirement" => "3.4.7" },
      { "name" => "nist-sp800-171", "version" => "r1", "requirement" => "3.4.8" },
      { "name" => "nist-sp800-171", "version" => "r1", "requirement" => "3.13.6" }
    ]
  )
  meta_rule_query <<~QUERY
  {
    sg as var(func: <%= filter['security_group'] %>) @cascade {
      ip as relates_to @filter(<%= filter['ip_permission'] %>) {
        protocol as ip_protocol
        port as from_port
        range as relates_to @filter(<%= filter['ip_range'] %>) {
          start as range_start
          end as range_end
          open as math(end - start == <%= 2**32 - 1 %>)
        }
      }
    }
    open_sg as query(func: uid(sg)) @cascade {
      <%= default_predicates %>
      group_id
      relates_to @filter(uid(ip) AND eq(val(protocol), "tcp") AND eq(val(port), 3306)) {
        <%= default_predicates %>
        ip_protocol
        from_port
        relates_to @filter(uid(range) AND eq(val(open), true)) {
          <%= default_predicates %>
          cidr_ip
        }
      }
    }
    visualize(func: uid(open_sg)) {
      <%= default_predicates %>
      group_name
      description
      relates_to {
        <%= default_predicates %>
        ip_protocol
        from_port
        to_port
        relates_to @filter(has(ip_range)) {
          <%= default_predicates %>
          cidr_ip
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
                            'security_group' => [],
                            'ip_permission' => ['ip_protocol', 'from_port'],
                            'ip_range' => ['cidr_ip']
                          })
end

coreo_aws_rule "ec2-TCP-5432-0.0.0.0-0" do
  action :define
  service :ec2
  link "https://kb.securestate.vmware.com/aws-ec2-tcpportopen.html"
  display_name "TCP port is open - 5432"
  description "Important TCP port is open and/or open to the world."
  category "Security"
  suggested_action "Only open those ports that must be open for your service to operate. Consider deleting or modifying the affected security group."
  level "Low"
  meta_nist_171_id "3.4.7, 3.4.8, 3.13.6"
  objectives ["","","security_groups"]
  audit_objects ["object.security_groups.ip_permissions.ip_protocol", "object.security_groups.ip_permissions.from_port", "object.security_groups.ip_permissions.ip_ranges.cidr_ip"]
  operators ["==","==","=="]
  raise_when ["tcp", 5432, "0.0.0.0/0"]
  id_map "object.security_groups.group_id"
  # TODO resolve for IPv6
  meta_compliance (
    [
      { "name" => "nist-sp800-171", "version" => "r1", "requirement" => "3.4.7" },
      { "name" => "nist-sp800-171", "version" => "r1", "requirement" => "3.4.8" },
      { "name" => "nist-sp800-171", "version" => "r1", "requirement" => "3.13.6" }
    ]
  )
  meta_rule_query <<~QUERY
  {
    sg as var(func: <%= filter['security_group'] %>) @cascade {
      ip as relates_to @filter(<%= filter['ip_permission'] %>) {
        protocol as ip_protocol
        port as from_port
        range as relates_to @filter(<%= filter['ip_range'] %>) {
          start as range_start
          end as range_end
          open as math(end - start == <%= 2**32 - 1 %>)
        }
      }
    }
    open_sg as query(func: uid(sg)) @cascade {
      <%= default_predicates %>
      group_id
      relates_to @filter(uid(ip) AND eq(val(protocol), "tcp") AND eq(val(port), 5432)) {
        <%= default_predicates %>
        ip_protocol
        from_port
        relates_to @filter(uid(range) AND eq(val(open), true)) {
          <%= default_predicates %>
          cidr_ip
        }
      }
    }
    visualize(func: uid(open_sg)) {
      <%= default_predicates %>
      group_name
      description
      relates_to {
        <%= default_predicates %>
        ip_protocol
        from_port
        to_port
        relates_to @filter(has(ip_range)) {
          <%= default_predicates %>
          cidr_ip
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
                            'security_group' => [],
                            'ip_permission' => ['ip_protocol', 'from_port'],
                            'ip_range' => ['cidr_ip']
                          })
end

coreo_aws_rule "ec2-TCP-27017-0.0.0.0-0" do
  action :define
  service :ec2
  link "https://kb.securestate.vmware.com/aws-ec2-tcpportopen.html"
  display_name "TCP port is open - 27017"
  description "Important TCP port is open and/or open to the world."
  category "Security"
  suggested_action "Only open those ports that must be open for your service to operate. Consider deleting or modifying the affected security group."
  level "Low"
  meta_nist_171_id "3.4.7, 3.4.8, 3.13.6"
  objectives ["","","security_groups"]
  audit_objects ["object.security_groups.ip_permissions.ip_protocol", "object.security_groups.ip_permissions.from_port", "object.security_groups.ip_permissions.ip_ranges.cidr_ip"]
  operators ["==","==","=="]
  raise_when ["tcp", 27017, "0.0.0.0/0"]
  id_map "object.security_groups.group_id"
  # TODO resolve for IPv6
  meta_compliance (
    [
      { "name" => "nist-sp800-171", "version" => "r1", "requirement" => "3.4.7" },
      { "name" => "nist-sp800-171", "version" => "r1", "requirement" => "3.4.8" },
      { "name" => "nist-sp800-171", "version" => "r1", "requirement" => "3.13.6" }
    ]
  )
  meta_rule_query <<~QUERY
  {
    sg as var(func: <%= filter['security_group'] %>) @cascade {
      ip as relates_to @filter(<%= filter['ip_permission'] %>) {
        protocol as ip_protocol
        port as from_port
        range as relates_to @filter(<%= filter['ip_range'] %>) {
          start as range_start
          end as range_end
          open as math(end - start == <%= 2**32 - 1 %>)
        }
      }
    }
    open_sg as query(func: uid(sg)) @cascade {
      <%= default_predicates %>
      group_id
      relates_to @filter(uid(ip) AND eq(val(protocol), "tcp") AND eq(val(port), 27017)) {
        <%= default_predicates %>
        ip_protocol
        from_port
        relates_to @filter(uid(range) AND eq(val(open), true)) {
          <%= default_predicates %>
          cidr_ip
        }
      }
    }
    visualize(func: uid(open_sg)) {
      <%= default_predicates %>
      group_name
      description
      relates_to {
        <%= default_predicates %>
        ip_protocol
        from_port
        to_port
        relates_to @filter(has(ip_range)) {
          <%= default_predicates %>
          cidr_ip
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
                            'security_group' => [],
                            'ip_permission' => ['ip_protocol', 'from_port'],
                            'ip_range' => ['cidr_ip']
                          })
end

coreo_aws_rule "ec2-TCP-1433-0.0.0.0-0" do
  action :define
  service :ec2
  link "https://kb.securestate.vmware.com/aws-ec2-tcpportopen.html"
  display_name "TCP port is open - 1433"
  description "Important TCP port is open and/or open to the world."
  category "Security"
  suggested_action "Only open those ports that must be open for your service to operate. Consider deleting or modifying the affected security group."
  level "Low"
  meta_nist_171_id "3.4.7, 3.4.8, 3.13.6"
  objectives ["","","security_groups"]
  audit_objects ["object.security_groups.ip_permissions.ip_protocol", "object.security_groups.ip_permissions.from_port", "object.security_groups.ip_permissions.ip_ranges.cidr_ip"]
  operators ["==","==","=="]
  raise_when ["tcp", 1433, "0.0.0.0/0"]
  id_map "object.security_groups.group_id"
  # TODO resolve for IPv6
  meta_compliance (
    [
      { "name" => "nist-sp800-171", "version" => "r1", "requirement" => "3.4.7" },
      { "name" => "nist-sp800-171", "version" => "r1", "requirement" => "3.4.8" },
      { "name" => "nist-sp800-171", "version" => "r1", "requirement" => "3.13.6" }
    ]
  )
  meta_rule_query <<~QUERY
  {
    sg as var(func: <%= filter['security_group'] %>) @cascade {
      ip as relates_to @filter(<%= filter['ip_permission'] %>) {
        protocol as ip_protocol
        port as from_port
        range as relates_to @filter(<%= filter['ip_range'] %>) {
          start as range_start
          end as range_end
          open as math(end - start == <%= 2**32 - 1 %>)
        }
      }
    }
    open_sg as query(func: uid(sg)) @cascade {
      <%= default_predicates %>
      group_id
      relates_to @filter(uid(ip) AND eq(val(protocol), "tcp") AND eq(val(port), 1433)) {
        <%= default_predicates %>
        ip_protocol
        from_port
        relates_to @filter(uid(range) AND eq(val(open), true)) {
          <%= default_predicates %>
          cidr_ip
        }
      }
    }
    visualize(func: uid(open_sg)) {
      <%= default_predicates %>
      group_name
      description
      relates_to {
        <%= default_predicates %>
        ip_protocol
        from_port
        to_port
        relates_to @filter(has(ip_range)) {
          <%= default_predicates %>
          cidr_ip
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
                            'security_group' => [],
                            'ip_permission' => ['ip_protocol', 'from_port'],
                            'ip_range' => ['cidr_ip']
                          })
end

coreo_aws_rule "ec2-TCP-3389-0.0.0.0-0" do
  action :define
  service :ec2
  link "https://kb.securestate.vmware.com/aws-ec2-tcpportopen.html"
  display_name "TCP port is open - 3389"
  description "Important TCP port is open and/or open to the world."
  category "Security"
  suggested_action "Only open those ports that must be open for your service to operate. Consider deleting or modifying the affected security group."
  meta_cis_id "4.2"
  meta_cis_scored "true"
  meta_cis_level "1"
  level "High"
  meta_nist_171_id "3.1.14, 3.13.6"
  objectives ["","","security_groups"]
  audit_objects ["object.security_groups.ip_permissions.ip_protocol", "object.security_groups.ip_permissions.from_port", "object.security_groups.ip_permissions.ip_ranges.cidr_ip"]
  operators ["==","==","=="]
  raise_when ["tcp", 3389, "0.0.0.0/0"]
  id_map "object.security_groups.group_id"
  # TODO resolve for IPv6
  meta_compliance (
    [
      { "name" => "nist-sp800-171", "version" => "r1", "requirement" => "3.1.14" },
      { "name" => "nist-sp800-171", "version" => "r1", "requirement" => "3.13.6" },
      { "name" => "cis-aws-foundations-benchmark", "version" => "1.2.0", "requirement" => "4.2" }
    ]
  )
  meta_rule_query <<~QUERY
  {
    sg as var(func: <%= filter['security_group'] %>) @cascade {
      ip as relates_to @filter(<%= filter['ip_permission'] %>) {
        protocol as ip_protocol
        port as from_port
        range as relates_to @filter(<%= filter['ip_range'] %>) {
          start as range_start
          end as range_end
          open as math(end - start == <%= 2**32 - 1 %>)
        }
      }
    }
    open_sg as query(func: uid(sg)) @cascade {
      <%= default_predicates %>
      group_id
      relates_to @filter(uid(ip) AND eq(val(protocol), "tcp") AND eq(val(port), 3389)) {
        <%= default_predicates %>
        ip_protocol
        from_port
        relates_to @filter(uid(range) AND eq(val(open), true)) {
          <%= default_predicates %>
          cidr_ip
        }
      }
    }
    visualize(func: uid(open_sg)) {
      <%= default_predicates %>
      group_name
      description
      relates_to {
        <%= default_predicates %>
        ip_protocol
        from_port
        to_port
        relates_to @filter(has(ip_range)) {
          <%= default_predicates %>
          cidr_ip
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
                            'security_group' => [],
                            'ip_permission' => ['ip_protocol', 'from_port'],
                            'ip_range' => ['cidr_ip']
                          })
end

coreo_aws_rule "ec2-TCP-22-0.0.0.0-0" do
  action :define
  service :ec2
  link "https://kb.securestate.vmware.com/aws-ec2-tcpportopen.html"
  display_name "TCP port is open - 22"
  description "Important TCP port is open and/or open to the world."
  category "Security"
  suggested_action "Only open those ports that must be open for your service to operate. Consider deleting or modifying the affected security group."
  meta_cis_id "4.1"
  meta_cis_scored "true"
  meta_cis_level "1"
  meta_nist_171_id "3.1.14, 3.13.6"
  level "High"
  objectives ["","","security_groups"]
  audit_objects ["object.security_groups.ip_permissions.ip_protocol", "object.security_groups.ip_permissions.from_port", "object.security_groups.ip_permissions.ip_ranges.cidr_ip"]
  operators ["==","==","=="]
  raise_when ["tcp", 22, "0.0.0.0/0"]
  id_map "object.security_groups.group_id"
  # TODO resolve for IPv6
  meta_compliance (
    [
      { "name" => "nist-sp800-171", "version" => "r1", "requirement" => "3.1.14" },
      { "name" => "nist-sp800-171", "version" => "r1", "requirement" => "3.13.6" },
      { "name" => "cis-aws-foundations-benchmark", "version" => "1.2.0", "requirement" => "4.1" }
    ]
  )
  meta_rule_query <<~QUERY
  {
    sg as var(func: <%= filter['security_group'] %>) @cascade {
      ip as relates_to @filter(<%= filter['ip_permission'] %>) {
        protocol as ip_protocol
        port as from_port
        range as relates_to @filter(<%= filter['ip_range'] %>) {
          start as range_start
          end as range_end
          open as math(end - start == <%= 2**32 - 1 %>)
        }
      }
    }
    open_sg as query(func: uid(sg)) @cascade {
      <%= default_predicates %>
      group_id
      relates_to @filter(uid(ip) AND eq(val(protocol), "tcp") AND eq(val(port), 22)) {
        <%= default_predicates %>
        ip_protocol
        from_port
        relates_to @filter(uid(range) AND eq(val(open), true)) {
          <%= default_predicates %>
          cidr_ip
        }
      }
    }
    visualize(func: uid(open_sg)) {
      <%= default_predicates %>
      group_name
      description
      relates_to {
        <%= default_predicates %>
        ip_protocol
        from_port
        to_port
        relates_to @filter(has(ip_range)) {
          <%= default_predicates %>
          cidr_ip
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
                            'security_group' => [],
                            'ip_permission' => ['ip_protocol', 'from_port'],
                            'ip_range' => ['cidr_ip']
                          })
end

coreo_aws_rule "ec2-TCP-5439-0.0.0.0-0" do
  action :define
  service :ec2
  link "https://kb.securestate.vmware.com/aws-ec2-tcpportopen.html"
  display_name "TCP port is open - 5439"
  description "Important TCP port is open and/or open to the world."
  category "Security"
  suggested_action "Only open those ports that must be open for your service to operate. Consider deleting or modifying the affected security group."
  level "Low"
  meta_nist_171_id "3.4.7, 3.4.8, 3.13.6"
  objectives ["","","security_groups"]
  audit_objects ["object.security_groups.ip_permissions.ip_protocol", "object.security_groups.ip_permissions.from_port", "object.security_groups.ip_permissions.ip_ranges.cidr_ip"]
  operators ["==","==","=="]
  raise_when ["tcp", 5439, "0.0.0.0/0"]
  id_map "object.security_groups.group_id"
  # TODO resolve for IPv6
  meta_compliance (
    [
      { "name" => "nist-sp800-171", "version" => "r1", "requirement" => "3.4.7" },
      { "name" => "nist-sp800-171", "version" => "r1", "requirement" => "3.4.8" },
      { "name" => "nist-sp800-171", "version" => "r1", "requirement" => "3.13.6" }
    ]
  )
  meta_rule_query <<~QUERY
  {
    sg as var(func: <%= filter['security_group'] %>) @cascade {
      ip as relates_to @filter(<%= filter['ip_permission'] %>) {
        protocol as ip_protocol
        port as from_port
        range as relates_to @filter(<%= filter['ip_range'] %>) {
          start as range_start
          end as range_end
          open as math(end - start == <%= 2**32 - 1 %>)
        }
      }
    }
    open_sg as query(func: uid(sg)) @cascade {
      <%= default_predicates %>
      group_id
      relates_to @filter(uid(ip) AND eq(val(protocol), "tcp") AND eq(val(port), 5439)) {
        <%= default_predicates %>
        ip_protocol
        from_port
        relates_to @filter(uid(range) AND eq(val(open), true)) {
          <%= default_predicates %>
          cidr_ip
        }
      }
    }
    visualize(func: uid(open_sg)) {
      <%= default_predicates %>
      group_name
      description
      relates_to {
        <%= default_predicates %>
        ip_protocol
        from_port
        to_port
        relates_to @filter(has(ip_range)) {
          <%= default_predicates %>
          cidr_ip
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
                            'security_group' => [],
                            'ip_permission' => ['ip_protocol', 'from_port'],
                            'ip_range' => ['cidr_ip']
                          })
end

coreo_aws_rule "ec2-TCP-23" do
  action :define
  service :ec2
  link "https://kb.securestate.vmware.com/aws-ec2-tcpportopen.html"
  display_name "TCP port is open - 23"
  description "Important TCP port is open and/or open to the world."
  category "Security"
  suggested_action "Only open those ports that must be open for your service to operate. Consider deleting or modifying the affected security group."
  level "Low"
  meta_nist_171_id "3.4.7, 3.4.8, 3.5.4"
  objectives ["","security_groups"]
  audit_objects ["object.security_groups.ip_permissions.ip_protocol", "object.security_groups.ip_permissions.from_port"]
  operators ["==","=="]
  raise_when ["tcp", 23]
  id_map "object.security_groups.group_id"
  meta_compliance (
    [
      { "name" => "nist-sp800-171", "version" => "r1", "requirement" => "3.4.7" },
      { "name" => "nist-sp800-171", "version" => "r1", "requirement" => "3.4.8" },
      { "name" => "nist-sp800-171", "version" => "r1", "requirement" => "3.5.4" }
    ]
  )
  meta_rule_query <<~QUERY
  {
    sg as var(func: <%= filter['security_group'] %>) @cascade {
      ip as relates_to @filter(<%= filter['ip_permission'] %>) {
        protocol as ip_protocol
        port as from_port
        range as relates_to @filter(has(ip_range))
      }
    }
    open_sg as query(func: uid(sg)) @cascade {
      <%= default_predicates %>
      group_id
      relates_to @filter(uid(ip) AND eq(val(protocol), "tcp") AND eq(val(port), 23)) {
        <%= default_predicates %>
        ip_protocol
        from_port
        relates_to @filter(uid(range)) {
          <%= default_predicates %>
          cidr_ip
        }
      }
    }
    visualize(func: uid(open_sg)) {
      <%= default_predicates %>
      group_name
      description
      relates_to {
        <%= default_predicates %>
        ip_protocol
        from_port
        to_port
        relates_to @filter(has(ip_range)) {
          <%= default_predicates %>
          cidr_ip
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers ({
                             'security_group' => [],
                             'ip_permission' => ['ip_protocol', 'from_port']
                           })
end

coreo_aws_rule "ec2-TCP-21" do
  action :define
  service :ec2
  link "https://kb.securestate.vmware.com/aws-ec2-tcpportopen.html"
  display_name "TCP port is open - 21"
  description "Important TCP port is open and/or open to the world."
  category "Security"
  suggested_action "Only open those ports that must be open for your service to operate. Consider deleting or modifying the affected security group."
  level "Low"
  meta_nist_171_id "3.4.7, 3.4.8, 3.5.4"
  objectives ["","security_groups"]
  audit_objects ["object.security_groups.ip_permissions.ip_protocol", "object.security_groups.ip_permissions.from_port"]
  operators ["==","=="]
  raise_when ["tcp", 21]
  id_map "object.security_groups.group_id"
  meta_compliance (
    [
      { "name" => "nist-sp800-171", "version" => "r1", "requirement" => "3.4.7" },
      { "name" => "nist-sp800-171", "version" => "r1", "requirement" => "3.4.8" },
      { "name" => "nist-sp800-171", "version" => "r1", "requirement" => "3.5.4" }
    ]
  )
  meta_rule_query <<~QUERY
  {
    sg as var(func: <%= filter['security_group'] %>) @cascade {
      ip as relates_to @filter(<%= filter['ip_permission'] %>) {
        protocol as ip_protocol
        port as from_port
        range as relates_to @filter(has(ip_range))
      }
    }
    open_sg as query(func: uid(sg)) @cascade {
      <%= default_predicates %>
      group_id
      relates_to @filter(uid(ip) AND eq(val(protocol), "tcp") AND eq(val(port), 21)) {
        <%= default_predicates %>
        ip_protocol
        from_port
        relates_to @filter(uid(range)) {
          <%= default_predicates %>
          cidr_ip
        }
      }
    }
    visualize(func: uid(open_sg)) {
      <%= default_predicates %>
      group_name
      description
      relates_to {
        <%= default_predicates %>
        ip_protocol
        from_port
        to_port
        relates_to @filter(has(ip_range)) {
          <%= default_predicates %>
          cidr_ip
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers ({
                             'security_group' => [],
                             'ip_permission' => ['ip_protocol', 'from_port']
                           })
end

coreo_aws_rule "ec2-TCP-20" do
  action :define
  service :ec2
  link "https://kb.securestate.vmware.com/aws-ec2-tcpportopen.html"
  display_name "TCP port is open - 20"
  description "Important TCP port is open and/or open to the world."
  category "Security"
  suggested_action "Only open those ports that must be open for your service to operate. Consider deleting or modifying the affected security group."
  level "Low"
  meta_nist_171_id "3.4.7, 3.4.8, 3.5.4"
  objectives ["","security_groups"]
  audit_objects ["object.security_groups.ip_permissions.ip_protocol", "object.security_groups.ip_permissions.from_port"]
  operators ["==","=="]
  raise_when ["tcp", 20]
  id_map "object.security_groups.group_id"
  meta_compliance (
    [
      { "name" => "nist-sp800-171", "version" => "r1", "requirement" => "3.4.7" },
      { "name" => "nist-sp800-171", "version" => "r1", "requirement" => "3.4.8" },
      { "name" => "nist-sp800-171", "version" => "r1", "requirement" => "3.5.4" }
    ]
  )
  meta_rule_query <<~QUERY
  {
    sg as var(func: <%= filter['security_group'] %>) @cascade {
      ip as relates_to @filter(<%= filter['ip_permission'] %>) {
        protocol as ip_protocol
        port as from_port
        range as relates_to @filter(has(ip_range))
      }
    }
    open_sg as query(func: uid(sg)) @cascade {
      <%= default_predicates %>
      group_id
      group_name
      description
      relates_to @filter(uid(ip) AND eq(val(protocol), "tcp") AND eq(val(port), 20)) {
        <%= default_predicates %>
        ip_protocol
        from_port
        to_port
        relates_to @filter(uid(range)) {
          <%= default_predicates %>
          cidr_ip
        }
      }
    }
    visualize(func: uid(open_sg)) {
      <%= default_predicates %>
      group_name
      description
      relates_to {
        <%= default_predicates %>
        ip_protocol
        from_port
        to_port
        relates_to @filter(has(ip_range)) {
          <%= default_predicates %>
          cidr_ip
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers ({
                             'security_group' => [],
                             'ip_permission' => ['ip_protocol', 'from_port']
                           })
end

coreo_aws_rule "ec2-TCP-8080" do
  action :define
  service :ec2
  link "https://kb.securestate.vmware.com/aws-ec2-tcpportopen.html"
  display_name "TCP port is open - 8080"
  description "Important TCP port is open and/or open to the world."
  category "Security"
  suggested_action "Only open those ports that must be open for your service to operate. Consider deleting or modifying the affected security group."
  level "Low"
  meta_nist_171_id "3.5.4"
  objectives ["","security_groups"]
  audit_objects ["object.security_groups.ip_permissions.ip_protocol", "object.security_groups.ip_permissions.from_port"]
  operators ["==","=="]
  raise_when ["tcp", 8080]
  id_map "object.security_groups.group_id"
  meta_compliance (
    [
      { "name" => "nist-sp800-171", "version" => "r1", "requirement" => "3.5.4" }
    ]
  )
  meta_rule_query <<~QUERY
  {
    sg as var(func: <%= filter['security_group'] %>) @cascade {
      ip as relates_to @filter(<%= filter['ip_permission'] %>) {
        protocol as ip_protocol
        port as from_port
        range as relates_to @filter(has(ip_range))
      }
    }
    open_sg as query(func: uid(sg)) @cascade {
      <%= default_predicates %>
      group_id
      relates_to @filter(uid(ip) AND eq(val(protocol), "tcp") AND eq(val(port), 8080)) {
        <%= default_predicates %>
        ip_protocol
        from_port
        relates_to @filter(uid(range)) {
          <%= default_predicates %>
          cidr_ip
        }
      }
    }
    visualize(func: uid(open_sg)) {
      <%= default_predicates %>
      group_name
      description
      relates_to {
        <%= default_predicates %>
        ip_protocol
        from_port
        to_port
        relates_to @filter(has(ip_range)) {
          <%= default_predicates %>
          cidr_ip
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers ({
                             'security_group' => [],
                             'ip_permission' => ['ip_protocol', 'from_port']
                           })
end

coreo_aws_rule "ec2-ports-range" do
  action :define
  service :ec2
  link "https://kb.securestate.vmware.com/aws-ec2-ports-range.html"
  display_name "Security group contains a port range"
  description "Security group contains a port range rather than individual ports."
  category "Security"
  suggested_action "Only add rules to your Security group that specify individual ports and don't use port ranges unless they are required."
  level "Low"
  meta_nist_171_id "3.4.7, 3.4.8"
  objectives ["security_groups"]
  audit_objects ["object.security_groups.ip_permissions.from_port"]
  operators ["!="]
  raise_when ["object[:to_port]"]
  id_map "object.security_groups.group_id"
  meta_compliance (
    [
      { "name" => "nist-sp800-171", "version" => "r1", "requirement" => "3.4.7" },
      { "name" => "nist-sp800-171", "version" => "r1", "requirement" => "3.4.8" }
    ]
  )
  meta_rule_query <<~QUERY
  {
    groups as var(func: <%= filter['security_group'] %> ) @cascade {
      permissions as relates_to @filter(<%= filter['ip_permission'] %> AND has(from_port) AND has(to_port)) {
        to_ports as to_port
        from_ports as from_port
        is_range as math(to_ports != from_ports)
      }
    }
    open_sg as query(func: uid(groups)) @cascade {
      <%= default_predicates %>
      group_id
      relates_to @filter(uid(permissions) AND eq(val(is_range), true)) {
        <%= default_predicates %> 
        from_port
        to_port
        ip_protocol
        is_range: val(is_range)
      }
    }
    visualize(func: uid(open_sg)) {
      <%= default_predicates %>
      group_name
      description
      relates_to {
        <%= default_predicates %>
        ip_protocol
        from_port
        to_port
        relates_to @filter(has(ip_range)) {
          <%= default_predicates %>
          cidr_ip
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers ({
                             'security_group' => [],
                             'ip_permission' => ['from_port', 'to_port']
                           })
end

coreo_aws_rule "ec2-not-used-security-groups" do
  action :define
  service :ec2
  display_name "EC2 security group is not used"
  description "Security group is not used anywhere"
  category "Security"
  suggested_action "Remove this security group"
  level "Low"
  meta_nist_171_id "3.4.6"
  objectives ["security_groups", "security_groups"]
  audit_objects ["object.security_groups", "object.group_name"]
  operators ["==", "!~"]
  raise_when [false, /^default$/]
  id_map "object.security_groups.group_id"
  meta_compliance (
    [
      { "name" => "nist-sp800-171", "version" => "r1", "requirement" => "3.4.6" }
    ]
  )
  meta_rule_query <<~QUERY
  { 
    filter as var(func: has(security_group)) @cascade { 
      relates_to @filter(NOT (has(owner) OR has(vpc) OR has(ip_permission) OR has(ip_permissions_egress))) { }
    } 
    open_sg as query(func: <%= filter['security_group'] %>) @filter(NOT uid(filter)) {
      <%= default_predicates %> 
      group_id 
    } 
    visualize(func: uid(open_sg)) {
      <%= default_predicates %>
      group_name
      description
      relates_to {
        <%= default_predicates %>
        ip_protocol
        from_port
        to_port
        relates_to @filter(has(ip_range)) {
          <%= default_predicates %>
          cidr_ip
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
                            'security_group' => []
                          })
end

coreo_aws_rule "ec2-default-security-group-traffic" do
  action :define
  service :ec2
  link "https://kb.securestate.vmware.com/aws-ec2-default-security-group-traffic.html"
  display_name "Default Security Group Unrestricted"
  description "The default security group settings should maximally restrict traffic"
  category "Security"
  suggested_action "Ensure default security groups are set to restrict all traffic"
  meta_cis_id "4.4"
  meta_cis_scored "true"
  meta_cis_level "2"
  level "Medium"
  meta_nist_171_id "3.4.7, 3.4.8"
  objectives ["security_groups", "security_groups"]
  audit_objects ["object.security_groups.group_name", "object.security_groups.ip_permissions"]
  operators ["==","!="]
  raise_when ["default", nil]
  id_map "object.security_groups.group_id"
  meta_compliance (
    [
      { "name" => "nist-sp800-171", "version" => "r1", "requirement" => "3.4.7" },
      { "name" => "nist-sp800-171", "version" => "r1", "requirement" => "3.4.8" },
      { "name" => "cis-aws-foundations-benchmark", "version" => "1.2.0", "requirement" => "4.4" }
    ]
  )
  meta_rule_query <<~QUERY
  {
    sg as var(func: has(security_group)) @cascade {
      gn as group_name
      relates_to @filter(has(ip_permission))
    }
    open_sg as query(func: uid(sg)) @filter(eq(val(gn), "default")) {
      <%= default_predicates %>
      group_id
    }
    visualize(func: uid(open_sg)) {
      <%= default_predicates %>
      group_name
      description
      relates_to {
        <%= default_predicates %>
        ip_protocol
        from_port
        to_port
        relates_to @filter(has(ip_range)) {
          <%= default_predicates %>
          cidr_ip
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
                            'security_group' => ['ip_permission']
                          })
end

coreo_aws_rule "ec2-vpc-flow-logs" do
  action :define
  service :user
  category "Audit"
  link "https://kb.securestate.vmware.com/aws-ec2-vpc-flow-logs.html"
  display_name "Ensure VPC flow logging is enabled in all VPCs (Scored)"
  suggested_action "VPC Flow Logs be enabled for packet 'Rejects' for VPCs."
  description "VPC Flow Logs is a feature that enables you to capture information about the IP traffic going to and from network interfaces in your VPC. After you've created a flow log, you can view and retrieve its data in Amazon CloudWatch Logs."
  level "Low"
  meta_cis_id "4.3"
  meta_cis_scored "true"
  meta_cis_level "1"
  meta_nist_171_id "3.13.1, 3.13.6"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [true]
  id_map "static.no_op"
  meta_compliance (
    [
      { "name" => "nist-sp800-171", "version" => "r1", "requirement" => "3.13.1" },
      { "name" => "nist-sp800-171", "version" => "r1", "requirement" => "3.13.6" },
      { "name" => "cis-aws-foundations-benchmark", "version" => "1.2.0", "requirement" => "4.3" }
    ]
  )
  meta_rule_query <<~QUERY
  {
    vpcs as var(func: <%= filter['vpc'] %>) @cascade {
      fl as relates_to @filter(<%= filter['flow_log'] %>) {
        fls as flow_log_status
      }
    }
    v as var(func: uid(vpcs)) @cascade {
      relates_to @filter(uid(fl) AND eq(val(fls), "ACTIVE"))
    }
    flow_log_enabled as query(func: <%= filter['vpc'] %>) @filter(NOT uid(v)) {
      <%= default_predicates %>
    }
    visualize(func: uid(flow_log_enabled)){
      <%= default_predicates %>
      relates_to @filter(NOT has(flow_log)) {
        <%= default_predicates %>
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
                              'vpc' => [],
                              'flow_log' => ['flow_log_status']
                          })
end
# end of user-visible content. Remaining resources are system-defined

coreo_aws_rule "ec2-security-groups-list" do
  action :define
  service :ec2
  include_violations_in_count false
  link "https://kb.securestate.vmware.com/aws-unused-alert-definition.html"
  display_name "CloudCoreo Use Only"
  description "This is an internally defined alert."
  category "Internal"
  suggested_action "Ignore"
  level "Internal"
  objectives ["security_groups"]
  audit_objects ["object.security_groups.group_name"]
  operators ["=~"]
  raise_when [//]
  id_map "object.security_groups.group_id"
end

coreo_aws_rule "ec2-instances-active-security-groups-list" do
  action :define
  service :ec2
  include_violations_in_count false
  link "https://kb.securestate.vmware.com/aws-unused-alert-definition.html"
  display_name "CloudCoreo Use Only"
  description "This is an internally defined alert."
  category "Internal"
  suggested_action "Ignore"
  level "Internal"
  objectives ["instances"]
  audit_objects ["object.reservations.instances.security_groups.group_id"]
  operators ["=~"]
  raise_when [//]
  id_map "object.reservations.instances.instance_id"
end

coreo_aws_rule "elb-instances-active-security-groups-list" do
  action :define
  service :elasticloadbalancing
  include_violations_in_count false
  link "https://kb.securestate.vmware.com/aws-unused-alert-definition.html"
  display_name "CloudCoreo Use Only"
  description "This is an internally defined alert."
  category "Internal"
  suggested_action "Ignore"
  level "Internal"
  objectives ["load_balancers"]
  audit_objects ["object.load_balancer_descriptions.security_groups"]
  operators ["=~"]
  raise_when [//]
  id_map "object.load_balancer_descriptions.load_balancer_name"
end

coreo_aws_rule "alb-instances-active-security-groups-list" do
  action :define
  service :elasticloadbalancingv2
  include_violations_in_count false
  link "https://kb.securestate.vmware.com/aws-unused-alert-definition.html"
  display_name "CloudCoreo Use Only"
  description "This is an internally defined alert."
  category "Internal"
  suggested_action "Ignore"
  level "Internal"
  objectives ["load_balancers"]
  audit_objects ["object.load_balancers.security_groups"]
  operators ["=~"]
  raise_when [//]
  id_map "object.load_balancers.load_balancer_name"
end

coreo_aws_rule "rds-instances-active-security-groups-list" do
  action :define
  service :rds
  include_violations_in_count false
  link "https://kb.securestate.vmware.com/aws-unused-alert-definition.html"
  display_name "CloudCoreo Use Only"
  description "This is an internally defined alert."
  category "Internal"
  suggested_action "Ignore"
  level "Internal"
  objectives ["db_instances"]
  audit_objects ["object.db_instances.vpc_security_groups.vpc_security_group_id"]
  operators ["=~"]
  raise_when [//]
  id_map "object.db_instances.db_instance_identifier"
end

coreo_aws_rule "redshift-instances-active-security-groups-list" do
  action :define
  service :redshift
  include_violations_in_count false
  link "https://kb.securestate.vmware.com/aws-unused-alert-definition.html"
  display_name "CloudCoreo Use Only"
  description "This is an internally defined alert."
  category "Internal"
  suggested_action "Ignore"
  level "Internal"
  objectives ["clusters"]
  audit_objects ["object.clusters.vpc_security_groups.vpc_security_group_id"]
  operators ["=~"]
  raise_when [//]
  id_map "object.clusters.cluster_identifier"
end

coreo_aws_rule "elasticache-instances-active-security-groups-list" do
  action :define
  service :elasticache
  include_violations_in_count false
  link "https://kb.securestate.vmware.com/aws-unused-alert-definition.html"
  display_name "CloudCoreo Use Only"
  description "This is an internally defined alert."
  category "Internal"
  suggested_action "Ignore"
  level "Internal"
  objectives ["cache_clusters"]
  audit_objects ["object.cache_clusters.security_groups.security_group_id"]
  operators ["=~"]
  raise_when [//]
  id_map "object.cache_clusters.cache_cluster_id"
end

coreo_aws_rule "vpc-inventory" do
  action :define
  service :ec2
  link "https://kb.securestate.vmware.com/aws-all-inventory.html"
  include_violations_in_count false
  display_name "Ensure VPC flow logging is enabled in all VPCs (Scored)"
  suggested_action "VPC Flow Logs be enabled for packet 'Rejects' for VPCs."
  description "VPC Flow Logs is a feature that enables you to capture information about the IP traffic going to and from network interfaces in your VPC. After you've created a flow log, you can view and retrieve its data in Amazon CloudWatch Logs."
  category "Audit"
  level "Internal"
  meta_cis_scored "true"
  meta_cis_level "1"
  objectives    ["vpcs"]
  audit_objects ["object.vpcs.vpc_id"]
  operators     ["=~"]
  raise_when    [//]
  id_map        "object.vpcs.vpc_id"
end

coreo_aws_rule "flow-logs-inventory" do
  action :define
  service :ec2
  link "https://kb.securestate.vmware.com/aws-all-inventory.html"
  include_violations_in_count false
  display_name "VPC for checking Flow logs"
  description "VPC flow logs rules"
  category "Audit"
  suggested_action "Enable Flow Logs"
  level "Internal"
  objectives    ["flow_logs"]
  audit_objects ["object.flow_logs.resource_id"]
  operators     ["=~"]
  raise_when    [//]
  id_map        "object.flow_logs.resource_id"
end

coreo_aws_rule_runner "vpcs-flow-logs-inventory" do
  action (("${AUDIT_AWS_EC2_ALERT_LIST}".include?("ec2-vpc-flow-logs")) ? :run : :nothing)
  service :ec2
  regions ${AUDIT_AWS_EC2_REGIONS}
  rules ["vpc-inventory", "flow-logs-inventory"]
  filter(${FILTERED_OBJECTS}) if ${FILTERED_OBJECTS}
end

coreo_uni_util_variables "ec2-planwide" do
  action :set
  variables([
                {'COMPOSITE::coreo_uni_util_variables.ec2-planwide.composite_name' => 'PLAN::stack_name'},
                {'COMPOSITE::coreo_uni_util_variables.ec2-planwide.plan_name' => 'PLAN::name'},
                {'COMPOSITE::coreo_uni_util_variables.ec2-planwide.results' => 'unset'},
                {'GLOBAL::number_violations' => '0'}
            ])
end

coreo_aws_rule_runner "advise-ec2" do
  service :ec2
  action :run
  rules (${AUDIT_AWS_EC2_ALERT_LIST} - ["flow-logs-inventory"])
  regions ${AUDIT_AWS_EC2_REGIONS}
  filter(${FILTERED_OBJECTS}) if ${FILTERED_OBJECTS}
end

coreo_aws_rule_runner "advise-unused-security-groups-ec2" do
  service :ec2
  action :run
  rules ["ec2-security-groups-list", "ec2-instances-active-security-groups-list"]
  regions ${AUDIT_AWS_EC2_REGIONS}
  filter(${FILTERED_OBJECTS}) if ${FILTERED_OBJECTS}
end

coreo_aws_rule_runner "advise-unused-security-groups-elb" do
  service :elasticloadbalancing
  action :run
  rules ["elb-instances-active-security-groups-list"]
  regions ${AUDIT_AWS_EC2_REGIONS}
  filter(${FILTERED_OBJECTS}) if ${FILTERED_OBJECTS}
end

coreo_aws_rule_runner "advise-unused-security-groups-alb" do
  service :elasticloadbalancingv2
  action :run
  rules ["alb-instances-active-security-groups-list"]
  regions ${AUDIT_AWS_EC2_REGIONS}
  filter(${FILTERED_OBJECTS}) if ${FILTERED_OBJECTS}
end

coreo_aws_rule_runner "advise-unused-security-groups-rds" do
  service :rds
  action :run
  rules ["rds-instances-active-security-groups-list"]
  regions ${AUDIT_AWS_EC2_REGIONS}
  filter(${FILTERED_OBJECTS}) if ${FILTERED_OBJECTS}
end

coreo_aws_rule_runner "advise-unused-security-groups-redshift" do
  service :redshift
  action :run
  rules ["redshift-instances-active-security-groups-list"]
  regions ${AUDIT_AWS_EC2_REGIONS}
  filter(${FILTERED_OBJECTS}) if ${FILTERED_OBJECTS}
end

coreo_aws_rule_runner "advise-unused-security-groups-elasticache" do
  service :elasticache
  action :run
  rules ["elasticache-instances-active-security-groups-list"]
  regions ${AUDIT_AWS_EC2_REGIONS}
  filter(${FILTERED_OBJECTS}) if ${FILTERED_OBJECTS}
end

coreo_uni_util_jsrunner "security-groups-ec2" do
  action :run
  json_input '{
      "main_report":COMPOSITE::coreo_aws_rule_runner.advise-ec2.report,
      "number_violations":COMPOSITE::coreo_aws_rule_runner.advise-ec2.number_violations,
      "ec2_report":COMPOSITE::coreo_aws_rule_runner.advise-unused-security-groups-ec2.report,
      "elb_report":COMPOSITE::coreo_aws_rule_runner.advise-unused-security-groups-elb.report,
      "alb_report":COMPOSITE::coreo_aws_rule_runner.advise-unused-security-groups-alb.report,
      "rds_report":COMPOSITE::coreo_aws_rule_runner.advise-unused-security-groups-rds.report,
      "redshift_report":COMPOSITE::coreo_aws_rule_runner.advise-unused-security-groups-redshift.report,
      "elasticache_report":COMPOSITE::coreo_aws_rule_runner.advise-unused-security-groups-elasticache.report
  }'
  function <<-EOH
const ruleMetaJSON = {
     'ec2-not-used-security-groups': COMPOSITE::coreo_aws_rule.ec2-not-used-security-groups.inputs
};
const ec2_alerts_list = ${AUDIT_AWS_EC2_ALERT_LIST};
if(!ec2_alerts_list.includes('ec2-not-used-security-groups')) {
  coreoExport('number_violations', JSON.stringify(COMPOSITE::coreo_aws_rule_runner.advise-ec2.number_violations));
  callback(json_input.main_report);
  return;
}
const ruleInputsToKeep = ['service', 'category', 'link', 'display_name', 'suggested_action', 'description', 'level', 'meta_cis_id', 'meta_cis_scored', 'meta_cis_level', 'include_violations_in_count'];
const ruleMeta = {};

Object.keys(ruleMetaJSON).forEach(rule => {
    const flattenedRule = {};
    ruleMetaJSON[rule].forEach(input => {
        if (ruleInputsToKeep.includes(input.name))
            flattenedRule[input.name] = input.value;
    })
    ruleMeta[rule] = flattenedRule;
})

const activeSecurityGroups = [];

// Only keep reports from json_input named *_report where * is not 'main'
const reports = Object.keys(json_input)
  .filter(key => key.match(/_report$/) && !(key === 'main_report'));
reports.forEach((report) => {
  Object.keys(json_input[report]).forEach((region) => {
    Object.keys(json_input[report][region]).forEach(key => {
      const service = report.split('_')[0];
      const violation = json_input[report][region][key].violations[`${service}-instances-active-security-groups-list`];
      if (!violation) return;
      violation.result_info.forEach((obj) => {
        switch (service) {
          case 'ec2':
            activeSecurityGroups.push(obj.object.group_id);
            break;
          case 'elb' || 'alb':
            obj.object.forEach(sg => activeSecurityGroups.push(sg));
            break;
          case 'rds' || 'redshift':
            activeSecurityGroups.push(obj.object.vpc_security_group_id);
            break;
          case 'elasticache':
            activeSecurityGroups.push(obj.object.security_group_id);
            break;
        }
      });
    });
  });
});
let number_violations = 0;
if (json_input['number_violations']) {
  number_violations = parseInt(json_input['number_violations']);
}
Object.keys(json_input.ec2_report).forEach((region) => {
  Object.keys(json_input.ec2_report[region]).forEach(key => {
    const tags = json_input.ec2_report[region][key].tags;
    const violations = json_input.ec2_report[region][key].violations["ec2-security-groups-list"];
    if (!violations) return;

    const currentSecGroup = violations['result_info'][0].object;
    if (activeSecurityGroups.includes(currentSecGroup.group_id)) return;
    number_violations++;
    const violationKey = 'ec2-not-used-security-groups';
    const securityGroupIsNotUsedAlert = {
        'display_name': 'EC2 security group is not used',
        'description': 'Security group is not used anywhere',
        'category': 'Audit',
        'suggested_action': 'Remove this security group',
        'level': 'Low',
        'region': violations.region,
        'meta_rule_query': `
                  {
                    vpcs as var(func: <%= filter['vpc'] %>) @cascade {
                      fl as relates_to @filter(<%= filter['flow_log'] %>) {
                        fls as flow_log_status
                      }
                    }
                    v as var(func: uid(vpcs)) @cascade {
                      relates_to @filter(uid(fl) AND eq(val(fls), "ACTIVE"))
                    }
                    query(func: has(vpc)) @filter(NOT uid(v)) {
                      <%= default_predicates %>
                      relates_to @filter(NOT has(flow_log)) {
                        <%= default_predicates %>
                      }
                    }
                  }`,
        'meta_rule_node_triggers': `{
                                      'vpc' => [],
                                      'flow_log' => ['flow_log_status']
                                    }`
    };
    Object.assign(securityGroupIsNotUsedAlert, ruleMeta[violationKey]);

    if (!json_input.main_report[region]) {
        json_input.main_report[region] = {};
    }
    if (!json_input.main_report[region][key]) {
        json_input.main_report[region][key] = { violations: {}, tags: [] };
    }
    json_input.main_report[region][key].violations[violationKey] = securityGroupIsNotUsedAlert;
    json_input.main_report[region][key].tags.concat(tags);
  });
});


coreoExport('number_violations', JSON.stringify(number_violations));

callback(json_input.main_report);
  EOH
end

coreo_uni_util_variables "ec2-update-planwide-2" do
  action :set
  variables([
                {'COMPOSITE::coreo_aws_rule_runner.advise-ec2.report' => 'COMPOSITE::coreo_uni_util_jsrunner.security-groups-ec2.return'},
                {'COMPOSITE::coreo_uni_util_variables.ec2-planwide.results' => 'COMPOSITE::coreo_uni_util_jsrunner.security-groups-ec2.return'},
                {'GLOBAL::number_violations' => 'COMPOSITE::coreo_uni_util_jsrunner.security-groups-ec2.number_violations'}
            ])
end

coreo_uni_util_jsrunner "cis43-processor" do
  action (("${AUDIT_AWS_EC2_ALERT_LIST}".include?("ec2-vpc-flow-logs")) ? :run : :nothing)
  json_input (("${AUDIT_AWS_EC2_ALERT_LIST}".include?("ec2-vpc-flow-logs")) ? '[COMPOSITE::coreo_aws_rule_runner.advise-ec2.report, COMPOSITE::coreo_aws_rule_runner.vpcs-flow-logs-inventory.report]' : '[]')
  function <<-'EOH'
  const ruleMetaJSON = {
      'ec2-vpc-flow-logs': COMPOSITE::coreo_aws_rule.ec2-vpc-flow-logs.inputs
  };
  const ruleInputsToKeep = ['service', 'category', 'link', 'display_name', 'suggested_action', 'description', 'level', 'meta_cis_id', 'meta_cis_scored', 'meta_cis_level', 'include_violations_in_count', 'meta_rule_query', 'meta_rule_node_triggers'];
  const ruleMeta = {};

  Object.keys(ruleMetaJSON).forEach(rule => {
      const flattenedRule = {};
      ruleMetaJSON[rule].forEach(input => {
          if (ruleInputsToKeep.includes(input.name))
              flattenedRule[input.name] = input.value;
      })
      ruleMeta[rule] = flattenedRule;
  })

  const VPC_FLOW_LOGS_RULE = 'ec2-vpc-flow-logs'
  const FLOW_LOGS_INVENTORY_RULE = 'flow-logs-inventory';
  const VPC_INVENTORY_RULE = 'vpc-inventory';

  const regionArrayJSON = "${AUDIT_AWS_EC2_REGIONS}";
  const regionArray = JSON.parse(regionArrayJSON.replace(/'/g, '"'))

  const vpcFlowLogsInventory = json_input[1];
  var json_output = json_input[0]

  const violations = copyViolationInNewJsonInput(regionArray, json_output);

  regionArray.forEach(region => {
      if (!vpcFlowLogsInventory[region]) return;

      const vpcs = Object.keys(vpcFlowLogsInventory[region]);

      vpcs.forEach(vpc => {
          if (!vpcFlowLogsInventory[region][vpc]['violations'][FLOW_LOGS_INVENTORY_RULE] || !verifyActiveFlowLogs(vpcFlowLogsInventory[region][vpc]['violations'][FLOW_LOGS_INVENTORY_RULE]['result_info'])) {
                updateOutputWithResults(region, vpc, vpcFlowLogsInventory[region][vpc]['violations'][VPC_INVENTORY_RULE]['result_info'], VPC_FLOW_LOGS_RULE);
          }
      })
  })

  function copyViolationInNewJsonInput(regions, input) {
      const output = {};
      regions.forEach(regionKey => {
          if (!input[regionKey]) {
            output[regionKey] = {};
          } else {
            output[regionKey] = input[regionKey]
          }
      });
      return output;
  }

  function updateOutputWithResults(region, vpcID, vpcDetails, rule) {
      if (!violations[region][vpcID]) {
          violations[region][vpcID] = {};
          violations[region][vpcID]['violator_info'] = vpcDetails;
      }
      if (!violations[region][vpcID]['violations']) {
          violations[region][vpcID]['violations'] = {};
      }

      var rule_value = JSON.parse(JSON.stringify(ruleMeta[rule]));
      rule_value['region'] = region
      rule_value['service'] = 'ec2'
      violations[region][vpcID]['violations'][rule] = rule_value;
  }

  function verifyActiveFlowLogs(results) {
      let flowLogsActive = false
      results.forEach(result => {
          const flow_log_status = result['object']['flow_log_status'];

          if (flow_log_status === 'ACTIVE') {
              flowLogsActive = true;
          }
      })

      return flowLogsActive;
  }

  callback(violations);
EOH
end

coreo_uni_util_variables "ec2-update-planwide-3" do
  action (("${AUDIT_AWS_EC2_ALERT_LIST}".include?("ec2-vpc-flow-logs")) ? :set : :nothing)
  variables([
                {'COMPOSITE::coreo_aws_rule_runner.advise-ec2.report' => 'COMPOSITE::coreo_uni_util_jsrunner.cis43-processor.return'}
            ])
end

coreo_uni_util_jsrunner "ec2-tags-to-notifiers-array" do
  action :run
  data_type "json"
  provide_composite_access true
  packages([
               {
                   :name => "cloudcoreo-jsrunner-commons",
                   :version => "1.10.7-beta64"
               },
               {
                   :name => "js-yaml",
                   :version => "3.7.0"
               }       ])
  json_input '{ "compositeName":"PLAN::stack_name",
                "planName":"PLAN::name",
                "teamName":"PLAN::team_name",
                "cloudAccountName": "PLAN::cloud_account_name",
                "violations": COMPOSITE::coreo_aws_rule_runner.advise-ec2.report}'
  function <<-EOH

const compositeName = json_input.compositeName;
const planName = json_input.planName;
const cloudAccount = json_input.cloudAccountName;
const cloudObjects = json_input.violations; 
const teamName = json_input.teamName;

const NO_OWNER_EMAIL = "${AUDIT_AWS_EC2_ALERT_RECIPIENT}";
const OWNER_TAG = "${AUDIT_AWS_EC2_OWNER_TAG}";
const ALLOW_EMPTY = "${AUDIT_AWS_EC2_ALLOW_EMPTY}";
const SEND_ON = "${AUDIT_AWS_EC2_SEND_ON}";
const htmlReportSubject = "${HTML_REPORT_SUBJECT}";

const alertListArray = ${AUDIT_AWS_EC2_ALERT_LIST};
const ruleInputs = {};

let userSuppression;
let userSchemes;

const fs = require('fs');
const yaml = require('js-yaml');
function setSuppression() {
  try {
      userSuppression = yaml.safeLoad(fs.readFileSync('./suppression.yaml', 'utf8'));
  } catch (e) {
    if (e.name==="YAMLException") {
      throw new Error("Syntax error in suppression.yaml file. "+ e.message);
    }
    else{
      console.log(e.name);
      console.log(e.message);
      userSuppression=[];
    }
  }

  coreoExport('suppression', JSON.stringify(userSuppression));
}

function setTable() {
  try {
    userSchemes = yaml.safeLoad(fs.readFileSync('./table.yaml', 'utf8'));
  } catch (e) {
    if (e.name==="YAMLException") {
      throw new Error("Syntax error in table.yaml file. "+ e.message);
    }
    else{
      console.log(e.name);
      console.log(e.message);
      userSchemes={};
    }
  }

  coreoExport('table', JSON.stringify(userSchemes));
}
setSuppression();
setTable();

const argForConfig = {
    NO_OWNER_EMAIL, cloudObjects, userSuppression, OWNER_TAG,
    userSchemes, alertListArray, ruleInputs, ALLOW_EMPTY,
    SEND_ON, cloudAccount, compositeName, planName, htmlReportSubject, teamName
}


function createConfig(argForConfig) {
    let JSON_INPUT = {
        compositeName: argForConfig.compositeName,
        htmlReportSubject: argForConfig.htmlReportSubject,
        planName: argForConfig.planName,
        teamName: argForConfig.teamName,
        violations: argForConfig.cloudObjects,
        userSchemes: argForConfig.userSchemes,
        userSuppression: argForConfig.userSuppression,
        alertList: argForConfig.alertListArray,
        disabled: argForConfig.ruleInputs,
        cloudAccount: argForConfig.cloudAccount
    };
    let SETTINGS = {
        NO_OWNER_EMAIL: argForConfig.NO_OWNER_EMAIL,
        OWNER_TAG: argForConfig.OWNER_TAG,
        ALLOW_EMPTY: argForConfig.ALLOW_EMPTY, SEND_ON: argForConfig.SEND_ON,
        SHOWN_NOT_SORTED_VIOLATIONS_COUNTER: false
    };
    return {JSON_INPUT, SETTINGS};
}

const {JSON_INPUT, SETTINGS} = createConfig(argForConfig);
const CloudCoreoJSRunner = require('cloudcoreo-jsrunner-commons');

const emails = CloudCoreoJSRunner.createEmails(JSON_INPUT, SETTINGS);
const suppressionJSON = CloudCoreoJSRunner.createJSONWithSuppress(JSON_INPUT, SETTINGS);

coreoExport('JSONReport', JSON.stringify(suppressionJSON));
coreoExport('report', JSON.stringify(suppressionJSON['violations']));

callback(emails);
  EOH
end

coreo_uni_util_variables "ec2-update-planwide-4" do
  action :set
  variables([
                {'COMPOSITE::coreo_aws_rule_runner.advise-ec2.report' => 'COMPOSITE::coreo_uni_util_jsrunner.ec2-tags-to-notifiers-array.report'},
                {'COMPOSITE::coreo_uni_util_variables.ec2-planwide.results' => 'COMPOSITE::coreo_uni_util_jsrunner.ec2-tags-to-notifiers-array.JSONReport'},
                {'GLOBAL::table' => 'COMPOSITE::coreo_uni_util_jsrunner.ec2-tags-to-notifiers-array.table'}
            ])
end


coreo_uni_util_jsrunner "ec2-tags-rollup" do
  action :run
  data_type "text"
  json_input 'COMPOSITE::coreo_uni_util_jsrunner.ec2-tags-to-notifiers-array.return'
  function <<-EOH
const notifiers = json_input;

function setTextRollup() {
    let emailText = '';
    let numberOfViolations = 0;
    let usedEmails=new Map();
    notifiers.forEach(notifier => {
        const hasEmail = notifier['endpoint']['to'].length;
        const email = notifier['endpoint']['to'];
        if(hasEmail && usedEmails.get(email)!==true) {
            usedEmails.set(email,true);
            numberOfViolations += parseInt(notifier['num_violations']);
            emailText += "recipient: " + notifier['endpoint']['to'] + " - " + "Violations: " + notifier['numberOfViolatingCloudObjects'] + ", Cloud Objects: "+ (notifier["num_violations"]-notifier['numberOfViolatingCloudObjects']) + "\\n";
        }
    });

    textRollup += 'Total Number of matching Cloud Objects: ' + numberOfViolations + "\\n";
    textRollup += 'Rollup' + "\\n";
    textRollup += emailText;

}


let textRollup = '';
setTextRollup();

callback(textRollup);
  EOH
end

coreo_uni_util_notify "advise-ec2-to-tag-values" do
  action((("${AUDIT_AWS_EC2_ALERT_RECIPIENT}".length > 0)) ? :notify : :nothing)
  notifiers 'COMPOSITE::coreo_uni_util_jsrunner.ec2-tags-to-notifiers-array.return'
end

coreo_uni_util_notify "advise-ec2-rollup" do
  action((("${AUDIT_AWS_EC2_ALERT_RECIPIENT}".length > 0) and (! "${AUDIT_AWS_EC2_OWNER_TAG}".eql?("NOT_A_TAG"))) ? :notify : :nothing)
  type 'email'
  allow_empty true
  send_on '${AUDIT_AWS_EC2_SEND_ON}'
  payload '
composite name: PLAN::stack_name
plan name: PLAN::name
COMPOSITE::coreo_uni_util_jsrunner.ec2-tags-rollup.return
  '
  payload_type 'text'
  endpoint ({
      :to => '${AUDIT_AWS_EC2_ALERT_RECIPIENT}', :subject => 'CloudCoreo ec2 rule results on PLAN::stack_name :: PLAN::name'
  })
end

coreo_aws_s3_policy "cloudcoreo-audit-aws-ec2-policy" do
  action((("${AUDIT_AWS_EC2_S3_NOTIFICATION_BUCKET_NAME}".length > 0) ) ? :create : :nothing)
  policy_document <<-EOF
{
"Version": "2012-10-17",
"Statement": [
{
"Sid": "",
"Effect": "Allow",
"Principal":
{ "AWS": "*" }
,
"Action": "s3:*",
"Resource": [
"arn:aws:s3:::${AUDIT_AWS_EC2_S3_NOTIFICATION_BUCKET_NAME}/*",
"arn:aws:s3:::${AUDIT_AWS_EC2_S3_NOTIFICATION_BUCKET_NAME}"
]
}
]
}
  EOF
end

coreo_aws_s3_bucket "bucket-${AUDIT_AWS_EC2_S3_NOTIFICATION_BUCKET_NAME}" do
  action((("${AUDIT_AWS_EC2_S3_NOTIFICATION_BUCKET_NAME}".length > 0) ) ? :create : :nothing)
  bucket_policies ["cloudcoreo-audit-aws-ec2-policy"]
end

coreo_uni_util_notify "cloudcoreo-audit-aws-ec2-s3" do
  action((("${AUDIT_AWS_EC2_S3_NOTIFICATION_BUCKET_NAME}".length > 0) ) ? :notify : :nothing)
  type 's3'
  allow_empty true
  payload 'COMPOSITE::coreo_uni_util_jsrunner.ec2-tags-to-notifiers-array.report'
  endpoint ({
      object_name: 'aws-ec2-json',
      bucket_name: '${AUDIT_AWS_EC2_S3_NOTIFICATION_BUCKET_NAME}',
      folder: 'ec2/PLAN::name',
      properties: {}
  })
end
