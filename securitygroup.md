It is virtual firewall for your ECS instances
- Blocks all traffic except the ports , protocols and sources you specify
- Define inbound and out bound rules
Rules are stateful

A VPC can have many subnets

security groups are related to EC2 instances

The security group should have a route that allows it to communicate with the internet through the internet gateway

you need a subnet to lauch resources


 failed: FATAL:  role "postgres" does not exist

 `psql postgres`

 by default `psql` tries to connect to postgres server using the same user name as your sustem user
 You can also remove the PostgreSQL user from your Mac system:

 `sudo dscl . -delete /Users/postgres`

 `sudo deluser postgres` for Ubuntu

 ```sh
 By default, Postgres uses a concept called “roles” to handle authentication and authorization. These are, in some ways, similar to regular Unix-style users and groups
 Upon installation, Postgres is set up to use ident authentication, meaning that it associates Postgres roles with a matching Unix/Linux system account. If a role exists within Postgres, a Unix/Linux username with the same name is able to sign in as that role.

 ```

 The installation procedure created a user account called `postgres` that is associated with the default Postgres role. There are a few ways to utilize this account to access Postgres. One way is to switch over to the `postgres` account on your server by running the following command:
 `sudo -i -u postgres`

 Then you can access the Postgres prompt by running: `psql`

 Another way to connect to the Postgres prompt is to run the `psql` command as the `postgres` account directly with sudo
 `sudo -u postgres psql`

 ### Creating a New Role
If you are logged in as the `postgres` account, you can create a new role by running the following command:
`createuser --interactive`

### Creating a New Database

Another assumption that the Postgres authentication system makes by default is that for any role used to log in, that role will have a database with the same name which it can access.

This means that if the user you created in the last section is called `sammy`, that role will attempt to connect to a database which is also called “sammy” by default. You can create the appropriate database with the `createdb` command.

`createdb sammy`

To log in with ident based authentication, you’ll need a Linux user with the same name as your Postgres role and database

`sudo adduser sammy`
`sudo -u sammy psql`

If you want your user to connect to a different database, you can do so by specifying the database like the following:
`psql -d postgres`


Security groups can be attached to multiple instances
An instance can have multiple security groups

A NAT Gateway  does network address translation(NAT) to allow an instance in a private subnet with private ip to connect to the internet for outbound access..It does not allow inbound access

