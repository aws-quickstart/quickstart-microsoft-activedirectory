[CmdletBinding()]
param(
	[Parameter(Position=0, Mandatory=$false)]
	[System.Int32]
	$count = 1,

	[Parameter(Position=1, Mandatory=$false)]
	[System.String]
	$password = [System.Web.Security.Membership]::GeneratePassword(10,2),
		
	[Parameter(Position=2, Mandatory=$false)]
	[System.String]
	$UpnSuffix = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().RootDomain.Name,

	[Parameter(Position=3, Mandatory=$false)]
	[System.String]
	$Description = "",	
	
	[Parameter(Position=4, Mandatory=$false)]
	[System.String]
	$OrganizationalUnit = ("CN=users," + ([ADSI]"LDAP://RootDSE").defaultNamingContext)
)

begin {
    $users = Import-Csv $PSScriptRoot\users.csv
}

process {
    $userpwd = ConvertTo-SecureString -AsPlainText $password -Force
	
    1..$count | %{
	    $r1 = Get-Random -Min 1 -Maximum 1000
	    $r2 = Get-Random -Min 1 -Maximum 1000
		
	    $firstname = $users[$r1].firstname
	    $lastname = $users[$r2].lastname
		
	    $upn = "$($firstname[0])$lastname@$UpnSuffix".ToLower()
	    $name = "$firstname $lastname"
	    $alias = "$($firstname[0])$lastname".ToLower()
		
	    New-ADUser -Name $name `
	    -GivenName $firstname `
	    -Surname $lastname `
	    -SamAccountName $alias `
	    -DisplayName $name `
	    -AccountPassword $userpwd `
	    -PassThru `
	    -Enabled $true `
	    -UserPrincipalName $upn `
	    -Description $Description `
	    -Path $OrganizationalUnit `
	    -EA 0
    }
}