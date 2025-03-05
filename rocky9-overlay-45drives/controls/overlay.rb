include_controls 'redhat-enterprise-linux-9-stig-baseline' do 

  control 'SV-258131' do

    only_if('If the System Administrator demonstrates the use of an approved alternate multifactor authentication method, this requirement is not applicable.', impact: 0.0) {
      !input('smart_card_enabled')
    }
  
    root_ca_file = input('root_ca_file')
    describe file(root_ca_file) do
      it { should exist }
    end
  
    #updating this from "DoD Root CA 3" to "DoD Root CA 6"
    describe 'Ensure the RootCA is a DoD-issued certificate with a valid date' do
      if file(root_ca_file).exist?
        subject { x509_certificate(root_ca_file) }
        it 'has the correct issuer_dn' do
          expect(subject.issuer_dn).to match('/C=US/O=U.S. Government/OU=DoD/OU=PKI/CN=DoD Root CA 6')
        end
        it 'has the correct subject_dn' do
          expect(subject.subject_dn).to match('/C=US/O=U.S. Government/OU=DoD/OU=PKI/CN=DoD Root CA 6')
        end
        it 'is valid' do
          expect(subject.validity_in_days).to be > 0
        end
      end
    end
  end

  control 'SV-257879' do
    all_args = command('blkid').stdout.strip.split("\n").map { |s| s.sub(/^"(.*)"$/, '\1') }
    def describe_and_skip(message)
      describe message do
        skip message
      end
    end

    # TODO: This should really have a resource
    if input('exempt_data_at_rest') == true
      impact 0.0
      describe_and_skip('Data At Rest Requirements have been set to Not Applicabe by the `exempt_data_at_rest` input.')
    elsif all_args.empty?
      # TODO: Determine if this is an NA vs and NR or even a pass
      describe_and_skip('Command blkid did not return and non-psuedo block devices.')
    else
      all_args.each do |args|
        # Removing the child partitions of the MD RAID. MDRAID partitions at the top are encrypted with LUKS.
        next if args =~ %r{/dev/sda|/dev/sdb|/dev/mapper|62f7e07d-fb92-4695-bc97-6f063a16722c|F61B-3482}

        describe args do
          it { should match(/\bcrypto_LUKS\b/) }
        end
      end
    end
  end
  
  control 'SV-258136' do
    file_integrity_tool = input('file_integrity_tool')

    only_if('Control not applicable within a container', impact: 0.0) do
      !virtualization.system.eql?('docker')
    end
    if file_integrity_tool == 'aide'
      describe parse_config_file('/etc/aide.conf') do
        its('ALL') { should match(/sha512/) }
      end
    else
      describe 'Manual Review' do
        skip "Review the selected file integrity tool (#{file_integrity_tool}) configuration to ensure it is using FIPS 140-2/140-3-approved cryptographic hashes for validating file contents and directories."
      end
    end
  end

  control 'SV-258105' do
    #made change to prevent 'nobody' user with UID 65534 from getting caught. 
    bad_users = users.where { uid >= 1000 }.where { uid != 65534 }.where { mindays < 1 }.usernames
    in_scope_users = bad_users - input('exempt_home_users')

    describe 'Users should not' do
      it 'be able to change their password more then once a 24 hour period' do
        failure_message = "The following users can update their password more then once a day: #{in_scope_users.join(', ')}"
        expect(in_scope_users).to be_empty, failure_message
      end
    end
  end

  control 'SV-257803' do
    if input('storing_core_dumps_required')
      impact 0.0
      describe 'N/A' do
        skip "Profile inputs indicate that this parameter's setting is a documented operational requirement"
      end
    else
      parameter = 'kernel.core_pattern'
      value = '|/bin/false'
      regexp = /^\s*#{parameter}\s*=\s*#{value}\s*$/

      describe kernel_parameter(parameter) do
        its('value') { should eq value }
      end

      search_results = command("/usr/lib/systemd/systemd-sysctl --cat-config | egrep -v '^(#|;)' | grep -F #{parameter}").stdout.strip.split("\n")

      correct_result = search_results.any? { |line| line.match(regexp) }
      incorrect_results = search_results.map(&:strip).reject { |line| line.match(regexp) }

      describe 'Kernel config files' do
        it "should configure '#{parameter}'" do
          expect(correct_result).to eq(true), 'No config file was found that correctly sets this action'
        end
        unless incorrect_results.nil?
          it 'should not have incorrect or conflicting setting(s) in the config files' do
            expect(incorrect_results).to be_empty, "Incorrect or conflicting setting(s) found:\n\t- #{incorrect_results.join("\n\t- ")}"
          end
        end
      end
    end
  end

  control 'SV-257823' do
    #misconfigured_files = command("rpm -Va --noconfig | awk '$1 ~ /..5/ && $2 != \"c\"'").stdout.strip.split("\n")

    #skipping these files as some were modified to meet other rules. 

    # Misconfigured files:
    # - S.5....T.    /usr/share/crypto-policies/FIPS/openssh.txt
    # - S.5....T.    /usr/share/crypto-policies/FIPS/opensshserver.txt
    # - S.5....T.    /usr/share/crypto-policies/back-ends/FIPS/opensshserver.config
    # - ..5....T.    /usr/lib/sysctl.d/10-default-yama-scope.conf
    # - S.5....T.    /usr/lib/sysctl.d/50-coredump.conf

    misconfigured_files = command("rpm -Va --noconfig | grep -v -e 'openssh.txt' -e 'opensshserver.txt' -e 'opensshserver.config' -e '10-default-yama-scope.conf' -e '50-coredump.conf' -e '50-redhat.conf' -e '50-default.conf' |  awk '$1 ~ /..5/ && $2 != \"c\"'").stdout.strip.split("\n")

    describe 'All system file hashes' do
      it 'should match vendor hashes' do
        expect(misconfigured_files).to be_empty, "Misconfigured files:\n\t- #{misconfigured_files.join("\n\t- ")}"
      end
    end
  end

  control 'SV-257936' do
    if input('external_firewall')
      message = 'This system uses an externally managed firewall service, verify with the system administrator that the firewall is configured to requirements'
      describe message do
        skip message
      end
    else
      describe package('firewalld') do
        it { should be_installed }
      end
      # modified the line below to look for systemd service
      describe systemd_service('firewalld') do
        it { should be_installed }
        it { should be_running }
      end
    end
  end

  control 'SV-257988' do
    
    # NOTE: -s to suppress errors if no files exist
    sshd_grep = command('grep -s Include /etc/ssh/sshd_config /etc/ssh/sshd_config.d/50-redhat.conf').stdout.lines.map(&:strip)

    # Check for specific Include directives
    star_dot_conf = sshd_grep.any? { |line| line.match?(%r{^/etc/ssh/sshd_config:Include /etc/ssh/sshd_config.d/\*\.conf$}i) }
    opensshserver_config = sshd_grep.any? { |line| line.match?(%r{^/etc/ssh/sshd_config.d/50-redhat.conf:Include /etc/crypto-policies/back-ends/opensshserver\.config$}i) }

    describe 'SSHD config files' do
      it 'should explicitly include /etc/ssh/sshd_config.d/*.conf in /etc/ssh/sshd_config' do
        expect(star_dot_conf).to eq(true), 'SSHD conf does not include /etc/ssh/sshd_config.d/*.conf in /etc/ssh/sshd_config'
      end

      it 'should explicitly include /etc/crypto-policies/back-ends/opensshserver.config in /etc/ssh/sshd_config.d/50-redhat.conf' do
        expect(opensshserver_config).to eq(true), 'SSHD conf does not include /etc/crypto-policies/back-ends/opensshserver.config in /etc/ssh/sshd_config.d/50-redhat.conf'
      end
    end
  end
end