include_controls 'redhat-enterprise-linux-8-stig-baseline' do 
  control 'SV-256973' do
    rpm_gpg_file = input('rpm_gpg_file')
    rpm_gpg_keys = input('rpm_gpg_keys')
  
    describe file(rpm_gpg_file) do
      it { should exist }
    end
    rpm_gpg_keys.each do |k, v|
      describe command('rpm -q --queryformat "%{SUMMARY}\\n" gpg-pubkey | grep -i "rocky"') do
        its('stdout') { should include k.to_s }
      end
      next unless file(rpm_gpg_file).exist?
  
      describe command("gpg -q --keyid-format short --with-fingerprint #{rpm_gpg_file}") do
        its('stdout') { should include v }
      end
    end
  end
end