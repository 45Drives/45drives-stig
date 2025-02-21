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

  control 'SV-230221' do
    release = os.release
    
    #changing the regex so '8.10' isn't caught by the '8.1' check
    EOMS_DATE = {
      /\b8\.1\b(?!\d)/ => '30 November 2021',
      /\b8\.2\b(?!\d)/ => '30 April 2022',
      /\b8\.3\b(?!\d)/ => '30 April 2021',
      /\b8\.4\b(?!\d)/ => '31 May 2023',
      /\b8\.5\b(?!\d)/ => '31 May 2022',
      /\b8\.6\b(?!\d)/ => '31 May 2024',
      /\b8\.7\b(?!\d)/ => '31 May 2023',
      /\b8\.8\b(?!\d)/ => '31 May 2025',
      /\b8\.9\b(?!\d)/ => '31 May 2024',
      /\b8\.10\b(?!\d)/ => '31 May 2029'
    }.find { |k, _v| k.match(release) }&.last

    describe "The release \"#{release}\" is still be within the support window" do
      it "ending on #{EOMS_DATE}" do
        expect(Date.today).to be <= Date.parse(EOMS_DATE)
      end
    end
  end
end