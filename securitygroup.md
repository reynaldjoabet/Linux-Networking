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



Internet Gateway allows communication between your VPC and the internet

enables inbound and outbound access to the internet
performs NAT for public instances

not a physical device
1 VPC, 1 Internet Gateway
No Cost

NAT Gateays allows outbound access, no inbound access

Using only layer 2, only those networks joined by a direct point to point ink using the SAME layer 2 protocol can communicate

Layer 2 Protocol
-  Ethernet (IEEE 802.3)
- Wi-Fi (IEEE 802.11)
- Fiber Optic Networks
- Bluetooth (IEEE 802.15.1)
- Cellular Networks (e.g., 4G, 5G)
- Coaxial Cable 

PPP

Ethernet is used for local networks
- It is the most popular wired connection technology for local area network

For point to point links and other long distance connections you might also use PPP, MPLS or ATM( more suitable protocols)

Their frames differ in format

To move data between two local networks, we need layer 3.it can span multiple layer 3 networks

Internet Protocol(IP) is a lyer-3 protocol which adds cross-network IP addeessing and routing to move data between local area networks without direct P2P links


It's the subnet mask which allows host to determine if an IP address it needs to communicate with is local or remote which influences if it needs to use a gateway or can communicate locally

A subnet or a sub network is a logical sub division of an IP network
The pratice of dividing a network into two or more networks is called subnetting

if you have a large number of devices in your LAN and want to divide it further, you have 2 ways:
- The layer 3 way- subnetting
- The layer 2 way- Vlan

[



5:23 / 25:54

•
Unicast vs Broadcast


Introduction to Network Access: VLANs and Subnets](https://www.youtube.com/watch?v=DvX7aWdqKss&t=329s)

A virtual local area network(VLAN) is a way to segment the network
If you have a variety of device types , you can separate dervices using VLANs to assign and restrict communication access

ingress controllr- reverse proxy for kubernetes

[


Skip navigation
Search





Avatar image



9:45 / 13:18

•
Bonus: Why you need Nginx reverse proxy for your Node.js app


Proxy vs Reverse Proxy vs Load Balancer](https://www.youtube.com/watch?v=xo5V9g9joFs&t=168s)

Nginx-- reverse proxy forwarding to appropriate back-end server

Nginx can also function as a kubernetes ingress controller

An ingress controller is a specialised load Balancer for managing ingress(incoming) traffic in kubernetes

it handles the routung to the appropriate services based on rules defined in an ingress resource

load balancer: Spread incoming traffic across multiple server instances
layer 4 or 7
nginx,aws elastic ld

Revere Proxy: sits infront of servers and acts as the entry point for all client and forwards them to backend servers
 performs load balancing
 
 - hides identity of backend servers
 - load distribution
 - ssl termination
 - compression
 - caching

Api gateway: An api gateway extends the concept of a reverse proxy by specifically  managing api requests.it serves as the main entry point for all api traffic, routing requests to the appropriate backend services

Besides routing, the api gateway handles tasks like authentication,logging, rate limiting and circuit breaking
kong, amazon api gateway

Forward Proxy


