Import-Module -Name ActiveDirectoryOperations

#region Tests for Add-KPMGGroupMember

    #tests when user and group names do not exist
    Add-KPMGGroupMember -Username 'testuser4' -GroupName 'testgroup4'
    #expected result: The username, testuser4 and group name, testgroup4 cannot be found.

    #tests when user does not exist
    Add-KPMGGroupMember -Username 'testuser4' -GroupName 'testgroup1'
    #expected result: The username, testuser4 cannot be found.

    #tests when group does not exist
    Add-KPMGGroupMember -Username 'testuser1' -GroupName 'testgroup4'
    #expected result: The group name, testgroup4 cannot be found.

    #tests when the user is already a member of the group
    Add-KPMGGroupMember -Username 'testuser1' -GroupName 'testgroup1'
    #expected result: The user, Test User 1 is already a member of testgroup1 so no further action is required

    #tests when the user is successfully added as a member of the group
    Add-KPMGGroupMember -Username 'testuser1' -GroupName 'testgroup2'
    #expected result: The user Test User 1 was added to the security group testgroup2 successfully

#endregion Tests for Add-KPMGGroupMember

#region Tests for Remove-KPMGGroupMember
    #tests when user and group names do not exist
    Remove-KPMGGroupMember -Username 'testuser4' -GroupName 'testgroup4'
    #expected result: The username, testuser4 and group name, testgroup4 cannot be found.

    #tests when user does not exist
    Remove-KPMGGroupMember -Username 'testuser4' -GroupName 'testgroup1'
    #expected result: The username, testuser4 cannot be found.

    #tests when group does not exist
    Remove-KPMGGroupMember -Username 'testuser1' -GroupName 'testgroup4'
    #expected result: The group name, testgroup4 cannot be found.

    #tests when the user is not a member of the group already
    Remove-KPMGGroupMember -Username 'testuser1' -GroupName 'testgroup3'
    #expected result: The username, testuser1 is not currently a member of testgroup3 so no further action is required

    #tests when the user is successfully removed as a member of the group
    Remove-KPMGGroupMember -Username 'testuser1' -GroupName 'testgroup2'
    #expected result: The user Test User 1 was removed from the security group testgroup2 successfully

    #tests when the 'EmptyGroup' switch is used to empty all users from a group (should leave nested groups intact)
    Remove-KPMGGroupMember -GroupName 'testgroup1' -EmptyGroup:$true
    #expected result: The following 3 users were removed from the security group testgroup1 : Test User 1 Test User 2 Test User 3

    #tests when the 'EmptyGroup' switch is used on a group with no members at all
    Remove-KPMGGroupMember -GroupName 'testgroup3' -EmptyGroup:$true
    #expected result: The security group testgroup3 did not contain any users at this time.  Nothing has been modified.

    #tests when the 'EmptyGroup' switch is False, but a username has also not been supplied
    Remove-KPMGGroupMember -GroupName 'testgroup2' -EmptyGroup:$false
    #expected result: A username was not supplied and the EmptyGroup parameter was false, therefore the command cannot continue

#endregion Tests for Remove-KPMGGroupMember

Remove-Module -Name ActiveDirectoryOperations