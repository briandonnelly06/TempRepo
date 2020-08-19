Function Add-KPMGGroupMember {
<#
   .SYNOPSIS
      Adds a user to an Active Directory security group.
   .DESCRIPTION
      This script will add a given user to a given Active Directory security group.
   .PARAMETER Username <String>
      The username of the user to be added
   .PARAMETER GroupName <String>
      The group name we are adding the user to.
   .INPUTS
      [String]
   .OUTPUTS

   .EXAMPLE
      Example of how to use this cmdlet
   .EXAMPLE
      Another example of how to use this cmdlet
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
   
   Import-Module -Name ActiveDirectory

   #Declare variables
   [string]$Message   
   [string]$Exception
   [Microsoft.ActiveDirectory.Management.ADUser]$ADUser
   [Microsoft.ActiveDirectory.Management.ADGroup]$ADgroup
   [Microsoft.ActiveDirectory.Management.ADPrincipal]$ADGroupMember
   [int]$Result = $null

   Try {
      #Get the AD user account and store in a variable
      $ADUser = Get-ADUser -Identity $Username -ErrorAction SilentlyContinue

      #Get the AD security group and store in a variable
      $ADgroup = Get-ADGroup -Identity $GroupName -ErrorAction SilentlyContinue

      #Checks to see whether our user is already a member of the group we are trying to add them to and stores in a variable
      $ADGroupMember = Get-ADGroupMember -Identity $GroupName | Where-Object -Property SamAccountName -eq $Username -ErrorAction SilentlyContinue

      #Condition where both the supplied user AND the supplied group are not returned
      If(($null -eq $ADUser) -AND ($null -eq $ADgroup)) {
         $Message = "The supplied username, " + $Username + " and group name, " + $GroupName + " cannot be found."
         $Result = 0
         $Exception = $($_.exception.message)
         #Throw $Message
      }
      #Condition where the supplied user is not returned
      ElseIf($null -eq $ADUser) {
         $Message = "The supplied username, " + $Username + " cannot be found."
         $Result = 0
         $Exception = $($_.exception.message)
         #Throw $Message
      }
      #Condition where the supplied group is not returned
      ElseIf($null -eq $ADgroup) {
         $Message = "The supplied group name, " + $Username + " cannot be found."
         $Result = 0
         $Exception = $($_.exception.message)
         #Throw $Message
      }
      #Condition where the user is already in the security group
      ElseIf(!($null -eq $ADGroupMember)) {
         $Message = "The supplied username, " + $Username + " is already a member of " + $GroupName + " so no further action is required"
         $Result = 1
         Write-Information -Message $Message
      }
      #If execution gets this far, the supplied user and group was returned, so we can attempt to add the user to the group.
      Else {
         #Add the supplied user to the AD group
         Add-ADGroupMember -Identity $ADgroup -Members $ADUser -ErrorAction SilentlyContinue | Out-Null
         
         #Checks to see whether our user is in the group we tried to add them to above and stores in a variable
         $ADGroupMember = Get-ADGroupMember -Identity $ADgroup | Where-Object -Property SamAccountName -eq $Username -ErrorAction SilentlyContinue

         #Condition where the result of the above is null and therefore, our user has not been added for some reason
         If($null -eq $ADGroupMember) {
            $Message = "Adding the user " + $Username + " to the security group " + $GroupName + " has failed."
            $Result = 0
            $Exception = $($_.exception.message)
         }
         #This means our user was added and we can notify the calling script this is the case
         Else {
            $Message = "The user " + $ADGroupMember.Name + " was added to the security group " + $GroupName + " successfully"
            $Result = 1
         }
      }
   }
   Catch {
      "ERROR: $($_.exception.message)"
   }
}

Function Remove-KPMGGroupMember {
   <#
   .SYNOPSIS
      Removes a single user from an Active Directory security group or empties the group of all users.
   .DESCRIPTION
      This script will remove a given user from a given Active Directory security group or will empty all users
      from the group if the EmptyGroup porameter is set to true.  Nested groups remain in place to maintain app
      support access.
   .PARAMETER Username <String>
      The username of the user to be removed
   .PARAMETER GroupName <String>
      The group name we are removing the user from.
   .PARAMETER EmptyGroup <switch>
      Set to false by default, but if set to true, will remove all user accounts from the supplied group.
   .INPUTS
      [String]
   .OUTPUTS

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
      [Parameter(Mandatory, HelpMessage="An AD username is needed")]
      [String]$Username,

      [Parameter(Mandatory, HelpMessage="An AD group name is needed")]
      [String]$GroupName,

      [Parameter(HelpMessage="If set to true, this will empty the whole group of users")]
      [switch]$EmptyGroup = "False"
   )
   
   Import-Module -Name ActiveDirectory

   #Declare variables
   [string]$Message
   [string]$Exception
   [Microsoft.ActiveDirectory.Management.ADUser]$ADUser
   [Microsoft.ActiveDirectory.Management.ADGroup]$ADgroup
   [Microsoft.ActiveDirectory.Management.ADPrincipal]$ADGroupMember
   [int]$Result

   Try {
      #Condition where the EmptyGroup parameter is true
      If("True" -eq $EmptyGroup) {
         Get-ADGroupMember -Recursive | Where-Object -Property ObjectClass -eq user | Remove-ADGroupMember -ErrorAction SilentlyContinue
         $ADGroupMember = Get-ADGroupMember -Identity $ADgroup | Where-Object -Property ObjectClass -eq user -ErrorAction SilentlyContinue

         #Condition where the result of the above is null and therefore, our group no longer contains any users
         If($null -eq $ADGroupMember) {
            $Message = "The security group " + $GroupName + " has been emptied of users successfully"
            $Result = 1
            Write-Verbose $Message
         }
         #This means our group still contains users so emptying the group has failed
         Else {
            $Message = "The security group " + $GroupName + " still contains users, so the command has failed."
            $Result = 0
            $Exception = $($_.exception.message)
            Throw $Message
         }
      }
      #EmptyGroup is false, so we are removing a single user.
      Else {
         #Get the AD user account and store in a variable
         $ADUser = Get-ADUser -Identity $Username -ErrorAction SilentlyContinue

         #Get the AD security group and store in a variable
         $ADgroup = Get-ADGroup -Identity $GroupName -ErrorAction SilentlyContinue

         #Checks to see whether our user is actually a member of the group we are trying to remove them from and stores in a variable
         $ADGroupMember = Get-ADGroupMember -Identity $ADgroup | Where-Object -Property SamAccountName -eq $Username -ErrorAction SilentlyContinue

         #Condition where both the supplied user AND the supplied group are not returned
         If(($null -eq $ADUser) -AND ($null -eq $ADgroup)) {
            $Message = "The supplied username, " + $Username + " and group name, " + $GroupName + " cannot be found."
            $Result = 0
            $Exception = $($_.exception.message)
            Throw $Message
         }
         #Condition where the supplied user is not returned
         ElseIf($null -eq $ADUser) {
            $Message = "The supplied username, " + $Username + " cannot be found."
            $Result = 0
            $Exception = $($_.exception.message)
            Throw $Message
         }
         #Condition where the supplied group is not returned
         ElseIf($null -eq $ADgroup) {
            $Message = "The supplied group name, " + $Username + " cannot be found."
            $Result = 0
            $Exception = $($_.exception.message)
            Throw $Message
         }
         #Condition where the user is not actually in the security group
         ElseIf($null -eq $ADGroupMember) {
            $Message = "The supplied username, " + $Username + " is not currently a member of " + $GroupName + " so no further action is required"
            $Result = 1
            Write-Verbose $Message
         }
         #If execution gets this far, the supplied user and group were returned and they are a member of this group, so we can attempt to remove the user from the group.
         Else {
            #Remove the supplied user to the AD group
            Remove-ADGroupMember -Identity $ADgroup -Members $ADUser -ErrorAction SilentlyContinue
            
            #Checks to see whether our user is in the group we tried to remove them from above and stores in a variable
            $ADGroupMember = $null
            $ADGroupMember = Get-ADGroupMember -Identity $ADgroup | Where-Object -Property SamAccountName -eq $Username -ErrorAction SilentlyContinue

            #Condition where the result of the above is null and therefore, our user is no longer in the security group
            If($null -eq $ADGroupMember) {
               $Message = "The user " + $Username + " was removed from the security group " + $GroupName + " successfully"
               $Result = 1
               Write-Verbose $Message
            }
            #This means our user was not removed from the security group because they are still a member
            Else {
               $Message = "Removing the user " + $ADGroupMember.Name + " from the security group " + $GroupName + " has failed."
               $Result = 0
               $Exception = $($_.exception.message)
               Throw $Message
            }
         }
      }
   }
   Catch {
      Write-Warning $ErrorMessage 
   }
}