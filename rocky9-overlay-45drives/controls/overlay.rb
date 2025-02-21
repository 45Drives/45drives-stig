include_controls 'redhat-enterprise-linux-9-stig-baseline' do 
  # control 'SV-257978' do
  #   openssh_present = package('openssh-server').installed?

  #   only_if('This requirement is Not Applicable in the container without open-ssh installed', impact: 0.0) {
  #     !(virtualization.system.eql?('docker') && !openssh_present)
  #   }

  #   if input('allow_container_openssh_server') == false
  #     describe 'In a container Environment' do
  #       it 'the OpenSSH Server should be installed only when allowed in a container environment' do
  #         expect(openssh_present).to eq(false), 'OpenSSH Server is installed but not approved for the container environment'
  #       end
  #     end
  #   else
  #     describe 'In a machine environment' do
  #       it 'the OpenSSH Server should be installed' do
  #         expect(package('openssh-server').installed?).to eq(true), 'the OpenSSH Server is not installed'
  #       end
  #     end
  #   end
  # end
  
  # control 'SV-258058' do
  #   known_system_accounts = input('known_system_accounts')
  #   user_accounts = input('user_accounts')

  #   failing_users = passwd.users.reject { |u| (known_system_accounts + user_accounts).uniq.include?(u) }

  #   describe 'All users' do
  #     it 'should have an explicit, authorized purpose (either a known user account or a required system account)' do
  #       expect(failing_users).to be_empty, "Failing users:\n\t- #{failing_users.join("\n\t- ")}"
  #     end
  #   end
  # end
  
  
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
  
  
  # control 'SV-257857' do
  #   option = 'noexec'
  #   file_systems = etc_fstab.params
  #   non_removable_media = input('non_removable_media_fs')
  #   mounted_removeable_media = file_systems.reject { |mnt| non_removable_media.include?(mnt['mount_point']) }
  #   failing_mounts = mounted_removeable_media.reject { |mnt| mnt['mount_options'].include?(option) }

  #   # be very explicit about why this one was a finding since we do not know which mounts are removeable media without the user telling us
  #   rem_media_msg = "NOTE: Some mounted devices are not indicated to be non-removable media (you may need to update the 'non_removable_media_fs' input to check if these are truly subject to this requirement)\n"

  #   # there should either be no mounted removable media (which should be a requirement anyway), OR
  #   # all removeable media should be mounted with noexec
  #   if mounted_removeable_media.empty?
  #     describe 'No removeable media' do
  #       it 'are mounted' do
  #         expect(mounted_removeable_media).to be_empty
  #       end
  #     end
  #   else
  #     describe 'Any mounted removeable media' do
  #       it "should have '#{option}' set" do
  #         expect(failing_mounts).to be_empty, "#{rem_media_msg}\nRemoveable media without '#{option}' set:\n\t- #{failing_mounts.join("\n\t- ")}"
  #       end
  #     end
  #   end
  # end

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
end