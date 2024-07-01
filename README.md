# CVE

Search for cve data from your command line

_Currently functions only on **UNIX based system**, i've gotta make some changes to the way it clears the terminal and installs itself in the path for others_

- _Held together by faith and duct tape_
- Has a very high chance of breaking previous functionalities after every commit

## Errors in Database?

_Very high chance that you'll have a few_

In case of errors in the database and you'll need to update a lot of the entries, you can get the hash id of a commit that's far back enough and change it the `previousCommit` file to start adjusting from that commit

## CVE conf template file

You are to create a your own file called `cve.conf` in the root folder of this package with everything provided in the `cve-template.conf` file, i am yet to find a better solution to making changes to the conf file without it overriding your personal configuration, so this is a temporary solution.
