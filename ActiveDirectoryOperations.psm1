Function Add-KPMGGroupMember {
<#
   .SYNOPSIS
      Adds a user to an Active Directory security group.
   .DESCRIPTION
      This script will add a user to an Active Directory security group.
   .PARAMETER Username <String>
      The username of the user to be added
   .PARAMETER GroupName <String>
      The group name we are adding the user to.
   .INPUTS
      [String]
   .OUTPUTS

   .EXAMPLE
      Add-KPMGGroupMember -Username 'testuser4' -GroupName 'testgroup4'
   .EXAMPLE
      Add-KPMGGroupMember -Username 'testuser1' -GroupName 'testgroup2'
   .NOTES
      Name Add-KPMGGroupMember
      Creator Brian Donnelly
      Date 18/08/2020
      Updated N/A
#>
   #requires -modules ActiveDirectory
   #requires -runasadministrator

   [CmdletBinding()]
   Param (
      [Parameter(Mandatory, HelpMessage="An AD username is needed")]
      [String]$Username,

      [Parameter(Mandatory, HelpMessage="An AD group name is needed")]
      [String]$GroupName
   )

   #Sets error prefrence to silently continue
   $ErrorActionPreference = "SilentlyContinue"

   #Imports the ActiveDirectory PowerShell module
   Import-Module -Name ActiveDirectory

   #Variables
   [String]$Message = "" #To store messages to be written to the event logs
   [string]$LogName = "User Access Management"
   [string]$LogSource = $MyInvocation.MyCommand

   #Create an event log and register this script as a source
   New-EventLog -LogName $LogName -Source $LogSource

   #Get the AD user account and store in a variable
   $ADUser = Get-ADUser -Identity $Username

   #Get the AD security group and store in a variable
   $ADgroup = Get-ADGroup -Identity $GroupName

   #Checks to see whether our user is already a member of the group we are trying to add them to and stores in a variable
   $ADGroupMember = Get-ADGroupMember -Identity $GroupName | Where-Object -Property SamAccountName -eq $Username

   #Condition where both the supplied user AND the supplied group are not returned
   If(($null -eq $ADUser) -AND ($null -eq $ADgroup)) {
      $Message = "The username, " + $Username + " and group name, " + $GroupName + " cannot be found."
      Write-EventLog -LogName $LogName -Source $LogSource -EntryType Error -EventId 1 -Message $Message
      Write-Verbose $Message
   }
   #Condition where the supplied user is not returned
   ElseIf($null -eq $ADUser) {
      $Message = "The username, " + $Username + " cannot be found."
      Write-EventLog -LogName $LogName -Source $LogSource -EntryType Error -EventId 2 -Message $Message
      Write-Verbose $Message
   }
   #Condition where the supplied group is not returned
   ElseIf($null -eq $ADgroup) {
      $Message = "The group name, " + $Username + " cannot be found."
      Write-EventLog -LogName $LogName -Source $LogSource -EntryType Error -EventId 3 -Message $Message
      Write-Verbose $Message
   }
   #Condition where the user is already in the security group
   ElseIf(!($null -eq $ADGroupMember)) {
      $Message = "The user, " + $ADUser.Name + " is already a member of " + $ADGroup.Name + " so no further action is required"
      Write-EventLog -LogName $LogName -Source $LogSource -EntryType Warning -EventId 4 -Message $Message
      Write-Verbose $Message
   }
   #If execution gets this far, the supplied user and group was returned, so we can attempt to add the user to the group.
   Else {
      Try {
         #Add the supplied user to the AD group
         Add-ADGroupMember -Identity $ADgroup -Members $ADUser
         
         #Checks to see whether our user is in the group we tried to add them to above and stores in a variable
         $ADGroupMember = Get-ADGroupMember -Identity $ADgroup | Where-Object -Property SamAccountName -eq $Username

         #Condition where the result of the above is null and therefore, our user has not been added for some reason
         If($null -eq $ADGroupMember) {
            $Message = "Adding the user " + $ADUser.Name + " to the security group " + $ADGroup.Name + " has failed."
            Write-EventLog -LogName $LogName -Source $LogSource -EntryType Error -EventId 5 -Message $Message
            Write-Verbose $Message
         }
         #This means our user was added and we can notify the calling script this is the case
         Else {
            $Message = "The user " + $ADUser.Name + " was added to the security group " + $ADGroup.Name + " successfully"
            Write-EventLog -LogName $LogName -Source $LogSource -EntryType Information -EventId 6 -Message $Message
            Write-Verbose $Message
         }
      }
      Catch {
      }
   }
}

Function Remove-KPMGGroupMember {
   <#
   .SYNOPSIS
      Removes a single user from an Active Directory security group or empties the group of all users.
   .DESCRIPTION
      This script will remove a given user from a given Active Directory security group or will empty all users
      from the group if the EmptyGroup porameter is set to $true.  Nested groups remain in place to maintain app
      support access.
   .PARAMETER Username <String>
      The username of the user to be removed
   .PARAMETER GroupName <String>
      The group name we are removing the user from.
   .PARAMETER EmptyGroup <switch>
      Set to $false by default, but if set to $true, will remove all user accounts from the supplied group.
   .INPUTS
      [String], [Switch]
   .OUTPUTS
      [string]
   .EXAMPLE
      Example of how to use this cmdlet
   .EXAMPLE
      Another example of how to use this cmdlet
   .NOTES
      Name Remove-KPMGGroupMember
      Creator Brian Donnelly
      Date 19/08/2020
      Updated N/A
#>
   #requires -modules ActiveDirectory
   #requires -runasadministrator

   [CmdletBinding()]
   Param (
      [Parameter(HelpMessage="An AD username is needed")]
      [String]$Username,

      [Parameter(Mandatory, HelpMessage="An AD group name is needed")]
      [String]$GroupName,

      [Parameter(HelpMessage="If set to true, this will empty the whole group of users")]
      [switch]$EmptyGroup = $false
   )
   
   #Sets error prefrence to silently continue
   $ErrorActionPreference = "SilentlyContinue"

   #Imports the ActiveDirectory PowerShell module
   Import-Module -Name ActiveDirectory

   #Variables
   [String]$Message = "" #To store messages to be written to the event logs
   [string]$LogName = "User Access Management"
   [string]$LogSource = $MyInvocation.MyCommand

   #Create an event log and register this script as a source
   New-EventLog -LogName $LogName -Source $LogSource

   #Condition where the EmptyGroup parameter is $true
   If($true -eq $EmptyGroup) {
      $ADGroupMemberPre = Get-ADGroupMember -Identity $GroupName -Recursive
      Get-ADGroupMember -Identity $GroupName -Recursive | ForEach-Object -Process {Remove-ADPrincipalGroupMembership -MemberOf $GroupName -Identity $($_.SamAccountName) -Confirm:$false }
      $ADGroupMember = Get-ADGroupMember -Identity $GroupName -Recursive

      #Condition where the value of $ADGroupMember is null and the value of $ADGroupMemberPre is not null (meaning users were in the group before)
      If(($null -eq $ADGroupMember) -and !($null -eq $ADGroupMemberPre)) {
         $Message = "The following " + $ADGroupMemberPre.Count + " users were removed from the security group " + $GroupName + " : " + $ADGroupMemberPre.Name
         Write-EventLog -LogName $LogName -Source $LogSource -EntryType Information -EventId 1 -Message $Message
         Write-Verbose $Message
      }
      #Condition where the value of $ADGroupMember is null and the value of $ADGroupMemberPre is null (meaning the group was empty of users before)
      ElseIf(($null -eq $ADGroupMember) -and ($null -eq $ADGroupMemberPre)) {
         $Message = "The security group " + $GroupName + " did not contain any users at this time.  Nothing has been modified."
         Write-EventLog -LogName $LogName -Source $LogSource -EntryType Warning -EventId 2 -Message $Message
         Write-Verbose $Message
      }
      #This means our group still contains users so emptying the group has failed
      Else {
         $Message = "The security group " + $GroupName + " still contains users, so the command has failed."
         Write-EventLog -LogName $LogName -Source $LogSource -EntryType Error -EventId 3 -Message $Message
         Write-Verbose $Message
      }
   }
   #Condition where EmptyGroup is $false, but no username has been supplied
   ElseIf(($false -eq $EmptyGroup) -and ("" -eq $Username)) {
      $Message = "A username was not supplied and the EmptyGroup parameter was false, therefore the command cannot continue"
      Write-EventLog -LogName $LogName -Source $LogSource -EntryType Error -EventId 4 -Message $Message
      Write-Verbose $Message
   }
   #EmptyGroup is false, so we are removing a single user.
   Else {
      #Get the AD user account and store in a variable
      $ADUser = Get-ADUser -Identity $Username

      #Get the AD security group and store in a variable
      $ADgroup = Get-ADGroup -Identity $GroupName

      #Checks to see whether our user is actually a member of the group we are trying to remove them from and stores in a variable
      $ADGroupMember = Get-ADGroupMember -Identity $ADgroup | Where-Object -Property SamAccountName -eq $Username

      #Condition where both the supplied user AND the supplied group are not returned
      If(($null -eq $ADUser) -AND ($null -eq $ADgroup)) {
         $Message = "The username, " + $Username + " and group name, " + $GroupName + " cannot be found."
         Write-EventLog -LogName $LogName -Source $LogSource -EntryType Error -EventId 5 -Message $Message
         Write-Verbose $Message
      }
      #Condition where the supplied user is not returned
      ElseIf($null -eq $ADUser) {
         $Message = "The username, " + $Username + " cannot be found."
         Write-EventLog -LogName $LogName -Source $LogSource -EntryType Error -EventId 6 -Message $Message
         Write-Verbose $Message
      }
      #Condition where the supplied group is not returned
      ElseIf($null -eq $ADgroup) {
         $Message = "The group name, " + $GroupName + " cannot be found."
         Write-EventLog -LogName $LogName -Source $LogSource -EntryType Error -EventId 7 -Message $Message
         Write-Verbose $Message
      }
      #Condition where the user is not actually in the security group
      ElseIf($null -eq $ADGroupMember) {
         $Message = "The username, " + $Username + " is not currently a member of " + $GroupName + " so no further action is required"
         Write-EventLog -LogName $LogName -Source $LogSource -EntryType Warning -EventId 8 -Message $Message
         Write-Verbose $Message
      }
      #If execution gets this far, the supplied user and group were returned and they are a member of this group, so we can attempt to remove the user from the group.
      Else {
         Try {
            #Remove the supplied user to the AD group
            Remove-ADGroupMember -Identity $ADgroup -Members $ADUser -Confirm:$false
            
            #Checks to see whether our user is in the group we tried to remove them from above and stores in a variable
            $ADGroupMember = $null
            $ADGroupMember = Get-ADGroupMember -Identity $ADgroup | Where-Object -Property SamAccountName -eq $Username

            #Condition where the result of the above is null and therefore, our user is no longer in the security group
            If($null -eq $ADGroupMember) {
               $Message = "The user " + $ADUser.Name + " was removed from the security group " + $ADGroup.Name + " successfully"
               Write-EventLog -LogName $LogName -Source $LogSource -EntryType Information -EventId 9 -Message $Message
               Write-Verbose $Message
            }
            #This means our user was not removed from the security group because they are still a member
            Else {
               $Message = "Removing the user " + $ADUser.Name + " from the security group " + $ADGroup.Name + " has failed."
               Write-EventLog -LogName $LogName -Source $LogSource -EntryType Error -EventId 10 -Message $Message
               Write-Verbose $Message
            }
         }
         Catch {
         }
      }
   }
}