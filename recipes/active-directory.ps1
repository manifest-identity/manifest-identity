# Active Directory group memberships to the observed table (subphase 1.14a).
#
# Run on a domain-joined machine with the ActiveDirectory module, as a
# reader of the directory:
#   pwsh recipes/active-directory.ps1 -Domain corp -Groups "Domain Admins","Backup Operators" > observed.csv
#
# One row per member per named group, members resolved recursively so
# a nested group's members appear with the hop written in the path.
# The identity is the security identifier, which the directory never
# reuses, and the kind is a person unless the account is disabled for
# interactive sign-in, which is the closest the directory comes to
# saying "service". Password age, last logon, service principal names,
# nesting, and control rights are not in this table; the native doors
# carry them (D-083, D-084), and this recipe remains for the table door.
param(
    [Parameter(Mandatory = $true)] [string] $Domain,
    [Parameter(Mandatory = $true)] [string[]] $Groups
)
Write-Output "provider,account,identity_id,identity_name,identity_type,identity_kind,role,role_name,mode,path"
foreach ($group in $Groups) {
    foreach ($member in Get-ADGroupMember -Identity $group -Recursive) {
        $direct = Get-ADGroupMember -Identity $group | Where-Object { $_.SID -eq $member.SID }
        $path = if ($direct) { "" } else { "membership:$group" }
        $kind = if ($member.objectClass -eq "user") { "person" } else { "service" }
        Write-Output ("active_directory,{0},{1},{2},{3},{4},{5},{5},standing,{6}" -f
            $Domain, $member.SID.Value, $member.SamAccountName, $member.objectClass, $kind, $group, $path)
    }
}
