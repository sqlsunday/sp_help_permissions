# sp_help_permissions

Copyright Daniel Hutmacher under [Creative Commons 4.0 license with attribution](http://creativecommons.org/licenses/by/4.0/).

Source: http://sqlsunday.com/downloads/

**WHAT:** This script lists all permissions by principal, securable and permission.
Optionally, you can filter these objects using the @principal, @securable,
and/or @permission parameters (using T-SQL wildcards).

The output can be tabular with permissions grouped as comma-separated lists
(using `@permission_list=1`) or one row for each permission (`@permission_list=0`).
You can also return the result as an xml OUTPUT variable, using @output_xml=1
and collecting the output from the @xml parameter.

**VERSION:** 2017-10-06

**DISCLAIMER:** This script does not make any modifications to the database
            apart from installing and registering a stored procedure
        in the master database, but may still not be suitable to run in
        a production environment. I cannot assume any responsibility
        with regards to the accuracy of the output information, any
        performance impact on your server, or any other consequence.
        It's free software, so you assume responsibility.
        If your juristiction does not allow for this kind of
        waiver/disclaimer, or if you do not accept these terms, you are
	    NOT allowed to store, distribute or use this code in any manner.
